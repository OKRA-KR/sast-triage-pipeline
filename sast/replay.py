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
import json, os, re, ssl, time, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qsl, urlencode
from .schema import new_finding
from .capture import _SQL_ERR, _IDOR_NAME, _body_params, _headers
from . import env

TIMEOUT = 10
MAX_REQ = int(os.environ.get("SAST_REPLAY_REQ", "600"))
DELAY = float(os.environ.get("SAST_REPLAY_DELAY", "0.05"))
XSS_MARK = "okr7xq<z>"
_LOGIN_SIG = re.compile(r"(login|signin|로그인|비밀번호|아이디를?\s*입력|인증이?\s*필요)", re.I)
_DROP_H = {"content-length", "host", "connection", "accept-encoding", "if-modified-since",
           "if-none-match", "cookie" if os.environ.get("SAST_HTTP_COOKIE") else ""}
_req = [0]
truncated = [False]     # 요청 상한 도달로 부분 스캔이 되었는가 (report meta 로 전달)
_warned = [False]


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def _send(method, url, headers, body):
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
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (e.read(80000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None


def _headers_for(ex, cookie=None):
    h = {k: v for k, v in ex["req_headers"].items() if k not in _DROP_H}
    ck = cookie or os.environ.get("SAST_HTTP_COOKIE")
    if ck:
        h["Cookie"] = ck
    return h


_STATIC = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map|txt|xml)$", re.I)
_PUBLIC = {"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"}


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


def scan_capture(exchanges, session=None, session_b=None):
    _req[0] = 0; _warned[0] = False; truncated[0] = False
    base_hosts = {ex["host"] for ex in exchanges if ex["host"]}
    ck_a = session.cookie if session else None
    mode = f" · 세션 A={session.label}" + (f", B={session_b.label} (IDOR 교차확증)" if session_b else "") if session else ""
    print(f"[*] replay 검증: 캡처 {len(exchanges)}건 · 호스트 {', '.join(sorted(base_hosts))} (인가 대상 전제·비파괴){mode}")
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
    print(f"[*] replay 검증: 요청 {_req[0]}건 · 확증/후보 {len(findings)}건")
    return findings


def _f(cat, sev, ex, key, payload, ev, verdict):
    loc = f"{ex['method']} {ex['path']}"
    return new_finding(
        fingerprint="replay-" + cat + "-" + re.sub(r"\W+", "", ex["path"])[-30:] + "-" + key,
        engines=["replay"], rule="replay-" + cat, full_rule="replay:" + cat, pack="replay-dast",
        category=cat, severity=sev, sev_lock=True, source="DAST", verdict=verdict, confidence=0.9,
        file=ex["url"].split("?")[0], line=0,
        message=f"[replay] {cat} — {loc} 파라미터 '{key}': {ev}",
        evidence=f"payload={payload} → {ev}",
        poc=f"{loc}  {key}={payload}  (캡처 세션 재전송)",
        dynamic={"status": "confirmed" if verdict == "true_positive" else "candidate", "evidence": ev})
