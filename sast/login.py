"""인증 세션 관리 — 도구가 직접 로그인해 싱싱한 세션 확보(만료 시 재로그인).

동기: 캡처의 세션 쿠키는 만료되면 모든 응답이 '로그인 리다이렉트'가 되어
replay 가 취약점·IDOR 을 전부 놓친다. 자격증명(ID/PW)으로 실제 로그인해
Set-Cookie 세션을 얻고, replay 도중 세션이 죽으면 자동 재로그인한다.

자격증명은 **코드에 없다** — 실행자가 환경변수로 주입:
  SAST_LOGIN_USER / SAST_LOGIN_PASS            (주 계정 A)
  SAST_LOGIN_USER2 / SAST_LOGIN_PASS2          (선택: 계정 B → 2계정 IDOR 확증)
로그인 요청 형태는 캡처의 로그인 요청에서 자동 추론(또는 SAST_LOGIN_URL 로 지정).
PW 는 로그에 마스킹. 인가 대상 전용.
"""
import os, re, ssl, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qsl, urlencode
from .capture import _AUTHFAIL, _body_params, _headers
from .schema import new_finding
from . import env

_USER_KEYS = re.compile(r"^(user_?id|userid|user_?nm|username|login_?id|mb_id|account|userno|memid|email|id|user)$", re.I)
_PW_KEYS = re.compile(r"^(pwd|passwd|password|user_?pw|passwrd|upw|pw|pass)$", re.I)
TIMEOUT = 10


def _ctx():
    return env.ssl_context()     # 기본 검증 on, SAST_INSECURE_TLS=1 시에만 비활성


def _mask(s):
    return (s[0] + "*" * (len(s) - 1)) if s else ""


_LOGIN_WORDS = ("login", "signin", "logon", "auth")
# 로그인 아닌 '비번성 키 보유' 요청(회원가입/비번변경/프로필수정 등) — 오선택 방지용 감점
_NEG_WORDS = ("logout", "register", "signup", "join", "save", "insert", "update",
              "modify", "change", "edit", "profile", "mypage", "find", "reset", "withdraw")


def derive_login(exchanges, explicit_url=None):
    """캡처에서 로그인 요청 추론 → (exchange, user_key, pw_key). 없으면 None.

    비번성 키를 가진 첫 요청을 무조건 택하지 않는다(회원가입/비번변경 오선택 방지).
    후보를 스코어링해 최적 1건 선택: SAST_LOGIN_URL 명시 > POST+login경로+user/pw 동시.
    """
    explicit_url = explicit_url or os.environ.get("SAST_LOGIN_URL")
    best, best_score = None, None
    for ex in exchanges:
        pairs = list(ex["query"]) + [(k, v) for k, v, _ in _body_params(ex)]
        names = [k for k, _ in pairs]
        pk = next((n for n in names if _PW_KEYS.match(n)), None)
        if not pk:
            continue
        uk = next((n for n in names if _USER_KEYS.match(n) and n != pk), None)
        if not uk:
            continue
        p = ex["path"].lower()
        score = 0
        if explicit_url and explicit_url in ex["url"]:
            score += 100
        if ex["method"] == "POST":
            score += 2
        if any(w in p for w in _LOGIN_WORDS):
            score += 5
        if any(w in p for w in _NEG_WORDS):
            score -= 4                       # 회원가입/비번변경/프로필 등 감점
        if len(names) <= 4:
            score += 1                       # 로그인은 보통 파라미터가 적다(id/pw/mode)
        if best_score is None or score > best_score:
            best_score, best = score, {"ex": ex, "user_key": uk, "pw_key": pk, "score": score}
    return best


def _cookie_from(headers):
    sc = headers.get("set-cookie", "")
    # 세션류 쿠키만 추출(PHPSESSID/JSESSIONID/여러 개면 name=value; 병합)
    parts = []
    for chunk in re.split(r",(?=[^ ;]+=)", sc):
        nv = chunk.split(";", 1)[0].strip()
        if "=" in nv and nv.split("=", 1)[1]:
            parts.append(nv)
    return "; ".join(parts)


_DROP = {"content-length", "host", "connection", "accept-encoding", "cookie"}
_LOGIN_SIG = re.compile(r"(login|signin|로그인|비밀번호|아이디를?\s*입력|인증이?\s*필요|세션이?\s*만료)", re.I)


class _NoRedirectH(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _apply_cred(h, cred):
    """세션 자격을 헤더에 적용 — 'Bearer …'면 Authorization, 아니면 Cookie."""
    if not cred:
        return
    h.pop("cookie", None); h.pop("authorization", None); h.pop("Cookie", None); h.pop("Authorization", None)
    if cred.startswith("Bearer "):
        h["Authorization"] = cred
    else:
        h["Cookie"] = cred


def _send_raw(method, url, headers, body, cookie=None):
    h = {k: v for k, v in headers.items() if k not in _DROP}
    if cookie:
        _apply_cred(h, cookie)
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method, headers={k: v for k, v in h.items() if k})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(40000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (e.read(40000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None


def _blocked(r):
    """접근 차단(비인증) 신호: 401/403·로그인 리다이렉트·로그인 화면."""
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


def pick_verify_ex(exchanges):
    """로그인 성공 검증용 — 캡처에서 인증됐던(auth) 비정적 GET 하나 선택."""
    for ex in exchanges:
        if ex["method"] != "GET":
            continue
        if not (ex["req_headers"].get("cookie") or ex["req_headers"].get("authorization")):
            continue
        p = ex["path"].lower()
        if any(w in p for w in ("login", "logout", "auth")) or re.search(r"\.(css|js|png|jpg|ico|txt|xml)$", p):
            continue
        return ex
    return None


_TOKEN_KEY = re.compile(r"csrf|xsrf|_token|authenticity|nonce|verificationtoken", re.I)
_BEARER_KEYS = ("access_token", "accessToken", "token", "jwt", "id_token", "idToken", "authToken")


def _extract_token(html, tkey):
    """HTML/응답에서 CSRF 토큰 값 추출(hidden input 순서 무관 + meta 태그)."""
    for pat in (r'name=["\']?%s["\']?[^>]*?value=["\']([^"\']+)',
                r'value=["\']([^"\']+)["\'][^>]*?name=["\']?%s'):
        m = re.search(pat % re.escape(tkey), html, re.I | re.S)
        if m:
            return m.group(1)
    m = re.search(r'<meta[^>]+(?:csrf|token)[^>]+content=["\']([^"\']+)', html, re.I)
    return m.group(1) if m else None


def _prime(template, cookie):
    """로그인 전 폼 페이지를 GET 해 **세션 쿠키를 먼저 확보**(Spring Security 등 세션 프라이밍)
    + CSRF 토큰이 있으면 신선한 값 추출. → (cookie, token_key, token_val).

    사전 세션 없이 로그인 POST 하면 실패하는 프레임워크(Spring/Django/…) 대응. 폼 페이지는
    Referer > 로그인 URL(GET) > origin 순으로 시도."""
    ex = template["ex"]
    names = [k for k, _ in ex["query"]] + [k for k, _, _ in _body_params(ex)]
    tkey = next((n for n in names if _TOKEN_KEY.search(n)), None)
    ref = ex["req_headers"].get("referer", "")
    pr = urlparse(ex["url"])
    for form_url in [u for u in (ref if ref.startswith("http") else None, ex["url"],
                                 f"{pr.scheme}://{pr.netloc}/") if u]:
        r = _send_raw("GET", form_url, {}, None, cookie)
        if not r:
            continue
        new_ck = _cookie_from(r[1])
        tval = _extract_token(r[2], tkey) if tkey else None
        if new_ck or tval:                      # 세션 또는 토큰 확보되면 사용
            return (new_ck or cookie), tkey, tval
    return cookie, tkey, None


def _bearer_from(rb):
    """JSON 로그인 응답에서 bearer 토큰 추출(access_token/token/jwt 등, data 중첩 포함)."""
    try:
        obj = __import__("json").loads(rb)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    src = dict(obj)
    if isinstance(obj.get("data"), dict):
        src.update(obj["data"])
    for k in _BEARER_KEYS:
        v = src.get(k)
        if isinstance(v, str) and len(v) > 10:
            return v
    return None


def authenticate(template, user, pw, cur_cookie=None, verify_ex=None):
    """로그인 요청 전송 → **양성 성공 검증** 통과 시 세션 자격(Cookie 또는 'Bearer …') 반환, 아니면 None.

    - CSRF 토큰 파라미터가 있으면 폼 페이지에서 신선한 토큰을 받아 주입(사이트 무관).
    - JSON 로그인은 응답의 bearer 토큰을 세션 자격으로 사용(Authorization 헤더).
    - 성공 판정: verify_ex(인증 엔드포인트) 프로브 통과 우선, 없으면 새 쿠키/토큰 발급.
    """
    ex = template["ex"]
    pr = urlparse(ex["url"])
    ct = (ex["req_headers"].get("content-type") or "").lower()
    hdr = {k: v for k, v in ex["req_headers"].items()
           if k not in ("content-length", "host", "connection", "accept-encoding")}
    # 세션 프라이밍(폼 페이지 GET → 세션쿠키 + CSRF 토큰)
    cur_cookie, tkey, tval = _prime(template, cur_cookie)
    if tkey and tval:
        print(f"[*] 로그인 CSRF 토큰 확보: {tkey}")
    hdr.pop("cookie", None)
    if cur_cookie:
        hdr["Cookie"] = cur_cookie

    def _setp(d):
        d[template["user_key"]] = user; d[template["pw_key"]] = pw
        if tkey:
            d[tkey] = tval
        return d
    body = None
    if ex["method"] == "POST" and "application/json" in ct:
        import json as _j
        try:
            obj = _j.loads(ex["req_body"] or "{}")
        except Exception:
            obj = {}
        body = _j.dumps(_setp(obj)); url = ex["url"]
    elif ex["method"] == "POST":
        body = urlencode(_setp(dict(parse_qsl(ex["req_body"] or "", keep_blank_values=True)))); url = ex["url"]
    else:
        url = pr._replace(query=urlencode(_setp(dict(parse_qsl(pr.query, keep_blank_values=True))))).geturl()
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=ex["method"],
                                 headers={k: v for k, v in hdr.items() if k})
    try:   # 리다이렉트 비추적 — 성공 302 의 Set-Cookie(새 세션)·Location 을 직접 확인
        opener = urllib.request.build_opener(_NoRedirectH, urllib.request.HTTPSHandler(context=_ctx()))
        with opener.open(req, timeout=TIMEOUT) as r:
            status = r.status; rb = r.read(20000).decode("utf-8", "replace")
            rh = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        status = e.code; rb = e.read(20000).decode("utf-8", "replace") if hasattr(e, "read") else ""
        rh = {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception as ex_e:
        print(f"[!] 로그인 요청 실패: {str(ex_e)[:100]}"); return None
    loc = rh.get("location", "")
    fail_redirect = 300 <= status < 400 and re.search(r"error|fail|invalid|denied|/login", loc, re.I)
    if _AUTHFAIL.search(rb) or fail_redirect:
        print(f"[!] 로그인 실패(자격증명 오류): user={_mask(user)}"); return None
    new_cookie = _cookie_from(rh)
    bearer = None if new_cookie else _bearer_from(rb)     # 쿠키 없으면 JSON bearer 시도
    # 성공: 새 세션쿠키 or (로그인 아닌 곳으로 302) or bearer → 그 자격 사용
    if new_cookie:
        cred = new_cookie
    elif bearer:
        cred = "Bearer " + bearer
    elif 300 <= status < 400:                             # 세션 유지한 채 성공 리다이렉트
        cred = cur_cookie
    else:
        cred = cur_cookie
    kind = "쿠키갱신" if new_cookie else ("Bearer토큰" if bearer else "세션유지")
    success_redirect = 300 <= status < 400 and not fail_redirect     # 로그인 아닌 곳으로 302 = 성공
    # ── 양성 성공 검증 ──
    if verify_ex is not None:
        pr2 = _send_raw(verify_ex["method"], verify_ex["url"], verify_ex["req_headers"], None, cred)
        if _blocked(pr2):
            print(f"[!] 로그인 검증 실패 — 세션 미확보(인증 엔드포인트 차단): user={_mask(user)}")
            return None
        print(f"[*] 로그인 성공(검증됨): user={_mask(user)} · {kind}")
        return cred
    if new_cookie or bearer or success_redirect or _resp_success(rb, rh, status):
        print(f"[*] 로그인 성공({kind}): user={_mask(user)}")
        return cred
    print(f"[!] 로그인 검증 불가 — 세션/토큰 미발급·프로브 대상 없음: user={_mask(user)} → 실패 처리")
    return None


class Session:
    """replay 가 쓰는 세션 핸들 — 쿠키 보관 + 만료 시 재로그인."""
    def __init__(self, template, user, pw, cookie=None, verify_ex=None):
        self.template, self.user, self.pw = template, user, pw
        self.cookie = cookie
        self.verify_ex = verify_ex
        self.label = _mask(user)

    def ensure(self):
        if not self.cookie:
            self.cookie = authenticate(self.template, self.user, self.pw, verify_ex=self.verify_ex)
        return self.cookie

    def reauth(self):
        self.cookie = authenticate(self.template, self.user, self.pw, self.cookie, self.verify_ex)
        return self.cookie


# ── 로그인 무차별 대입(브루트포스) — 옵트인·인가 대상 전용 ──────────────
WEAK_PW = ["1234", "12345", "123456", "1111", "0000", "admin", "password", "passwd",
           "test", "qwerty", "1q2w3e", "p@ssw0rd", "asdf", "12341234", "a1234567",
           "<user>", "<user>123", "<user>1234"]
# 사이트 무관 성공 '힌트'(문자열은 보조 신호일 뿐 — 핵심은 새 세션쿠키/리다이렉트/실패대비 차등)
_SUCCESS_HINT = re.compile(r"success|\btoken\b|access_token|welcome|dashboard|logout|로그아웃|"
                           r"로그인\s*성공|\"result\"\s*:\s*(?:true|1|\"?success)", re.I)
# 락아웃/레이트리밋 신호 (정상 '비밀번호 틀림'과 구분 — _blocked 의 로그인문구와 혼동 금지)
_LOCKOUT = re.compile(r"too\s*many|locked|lockout|rate.?limit|잠(?:금|겼|김)|차단|일시(?:적|정지)|"
                      r"시도.*제한|제한.*시도|blocked", re.I)


def _resp_success(rb, rh, status=None):
    """사이트 무관 로그인 성공 판정(행위 우선). 실패(_AUTHFAIL/로그인화면)면 False.
    새 세션쿠키 발급 · 3xx 리다이렉트 · 성공 힌트(logout/token/welcome/success/...) 중 하나면 True."""
    rb = rb or ""
    if _AUTHFAIL.search(rb):
        return False
    if _cookie_from(rh or {}):                       # 새 세션 발급 = 강한 성공 신호
        return True
    if status and 300 <= int(status) < 400:          # 대시보드로 리다이렉트
        return True
    if _SUCCESS_HINT.search(rb) and not _LOGIN_SIG.search(rb):
        return True
    return False


def _login_ok(rb, rh, status=None):
    return _resp_success(rb, rh, status)


def _attempt(template, user, pw):
    """로그인 1회 시도 → 'success' | 'fail' | 'blocked' | None(오류)."""
    ex = template["ex"]
    pr = urlparse(ex["url"])
    ct = (ex["req_headers"].get("content-type") or "").lower()
    hdr = {k: v for k, v in ex["req_headers"].items() if k not in _DROP}

    def sub(pairs):
        d = dict(pairs); d[template["user_key"]] = user; d[template["pw_key"]] = pw
        return urlencode(d)
    if ex["method"] == "POST" and "application/json" in ct:
        import json as _j
        try:
            obj = _j.loads(ex["req_body"] or "{}")
        except Exception:
            obj = {}
        obj[template["user_key"]] = user; obj[template["pw_key"]] = pw
        url, body = ex["url"], _j.dumps(obj)
    elif ex["method"] == "POST":
        url, body = ex["url"], sub(parse_qsl(ex["req_body"] or "", keep_blank_values=True))
    else:
        url, body = pr._replace(query=sub(parse_qsl(pr.query, keep_blank_values=True))).geturl(), None
    r = _send_raw(ex["method"], url, hdr, body)
    if not r:
        return None
    if r[0] in (429, 403) or _LOCKOUT.search(r[2][:800]):   # 락아웃/레이트리밋(정상 실패와 구분)
        return "blocked"
    return "success" if _login_ok(r[2], r[1], r[0]) else "fail"


def brute_force(exchanges, user, words=None, cap=None):
    """인가 대상 전용 로그인 무차별 대입. 약한 자격증명·락아웃 부재 탐지 → findings 반환.

    ⚠ 계정 잠금(lockout)·실계정 영향 위험 → 본인/테스트 계정에만. 성공 시 즉시 중단.
    """
    tmpl = derive_login(exchanges)
    if not tmpl:
        print("[!] 브루트포스: 로그인 요청 추론 실패 — 캡처에 로그인 트래픽 필요"); return []
    cap = cap or int(os.environ.get("SAST_BRUTE_MAX", "25"))
    words = [w.replace("<user>", user) for w in (words or WEAK_PW)][:cap]
    print(f"[!] 로그인 브루트포스(인가 전용) — user={_mask(user)} · 사전 {len(words)}개")
    print("    ⚠ 계정 잠금 위험 — 본인/테스트 계정만. 락아웃 감지 시 자동 중단.")
    tried = 0; found = None; lockout = False
    for pw in words:
        tried += 1
        st = _attempt(tmpl, user, pw)
        if st == "blocked":
            lockout = True; break
        if st == "success":
            found = pw; break
    ex = tmpl["ex"]
    loc = f"{ex['method']} {ex['path']}"
    findings = []
    if found:
        findings.append(new_finding(
            fingerprint="brute-weakcred-" + user, engines=["brute"], rule="weak-credential",
            full_rule="brute:weak-credential", pack="brute", category="broken-auth",
            severity="high", sev_lock=True, source="DAST", verdict="true_positive", confidence=0.95,
            file=ex["url"].split("?")[0], line=0,
            message=f"[brute] 약한 자격증명 — user '{_mask(user)}' 사전공격 성공({loc})",
            evidence=f"{tried}회 내 성공 · pw={_redact(found)}",
            dynamic={"status": "confirmed", "evidence": f"사전 {tried}회 내 로그인 성공"},
            rationale="사전(약한 비밀번호) 무차별 대입으로 로그인 성공 → 약한 자격증명 + 무차별대입 방어 미흡."))
    elif not lockout and tried >= 10:
        findings.append(new_finding(
            fingerprint="brute-nolockout-" + ex["path"], engines=["brute"], rule="no-account-lockout",
            full_rule="brute:no-account-lockout", pack="brute", category="missing-anti-automation",
            severity="medium", sev_lock=True, source="DAST", verdict="needs_review", confidence=0.7,
            file=ex["url"].split("?")[0], line=0,
            message=f"[brute] 로그인 무차별 대입 방어 부재 — {tried}회 시도에도 잠금/차단 없음({loc})",
            evidence=f"{tried}회 연속 로그인 시도 허용(락아웃/레이트리밋 미발생)",
            rationale="연속 로그인 실패에도 계정 잠금·레이트리밋이 없어 무차별 대입·크리덴셜 스터핑에 노출."))
    if lockout:
        print(f"[*] 브루트포스: {tried}회에서 차단(락아웃/레이트리밋 감지) — 방어 동작")
    return findings


def _redact(s):
    return (s[0] + "*" * (len(s) - 1)) if s else ""


def working_session(exchanges):
    """전체 점검(--full)용 — '작동하는 인증 세션'을 확보한다. → (ok, sess_a, sess_b).

    우선순위: 로그인(env 자격증명 또는 캡처의 성공 로그인 자동추출) > 유효 쿠키(--cookie/캡처).
    - 로그인: build_sessions 로 신선한 세션 확보. 성공하면 ok=True.
    - 쿠키만: 캡처의 인증 엔드포인트로 프로브해 차단이면 ok=False(만료/무효). 검증불가면 통과.
    - 둘 다 없음: ok=False (계정 없음 → 호출측이 종료).
    """
    a, b = build_sessions(exchanges)         # env 자격증명 또는 캡처 자동추출로 로그인
    if a is not None:
        return True, a, b
    ck = os.environ.get("SAST_HTTP_COOKIE")
    if ck:
        vx = pick_verify_ex(exchanges)
        if vx is None:
            print("[*] 쿠키 유효성 검증용 인증 엔드포인트 없음 — 제공된 쿠키로 진행")
            return True, None, None
        r = _send_raw(vx["method"], vx["url"], vx["req_headers"], None, ck)
        if _blocked(r):
            print("[!] 제공된 세션 쿠키가 무효/만료 — 인증 엔드포인트 접근 차단됨")
            return False, None, None
        print("[*] 세션 쿠키 유효 확인")
        return True, None, None
    return False, None, None


def _login_creds(ex, uk, pk):
    vals = dict(ex["query"]); vals.update({k: v for k, v, _ in _body_params(ex)})
    return vals.get(uk), vals.get(pk)


def derive_credentials(exchanges, template):
    """캡처의 '성공한 로그인' 요청에서 user/pw 추출 → 자동 로그인용(사이트 무관). 없으면 None.

    성공 판정은 행위 기반(_resp_success): 새 세션쿠키·리다이렉트·성공힌트. 특정 사이트 문자열에
    의존하지 않는다. 명확한 성공이 없으면, 다수(실패)와 '다른' 응답의 로그인을 성공 후보로 본다.
    """
    uk, pk = template["user_key"], template["pw_key"]
    lp = template["ex"]["path"]
    cands = [ex for ex in exchanges if ex["path"] == lp and all(_login_creds(ex, uk, pk))]
    if not cands:
        return None
    # 1) 행위 기반 성공 응답
    for ex in cands:
        rh = _headers(ex.get("resp_headers", "") or "")
        st = ex.get("status") if str(ex.get("status", "")).isdigit() else None
        if _resp_success(ex.get("resp_body", "") or "", rh, st):
            return _login_creds(ex, uk, pk)
    # 2) 차등 폴백 — 실패 응답이 다수 클러스터를 이루면, 그와 '다른' 응답이 성공 후보
    from collections import Counter
    def sig(ex):
        body = ex.get("resp_body", "") or ""
        return (str(ex.get("status", "")), len(body) // 64, bool(_AUTHFAIL.search(body)))
    sigs = [sig(ex) for ex in cands]
    if len(set(sigs)) > 1:
        common = Counter(sigs).most_common(1)[0][0]
        for ex in cands:
            if sig(ex) != common and not _AUTHFAIL.search(ex.get("resp_body", "") or ""):
                return _login_creds(ex, uk, pk)
    return None


def build_sessions(exchanges):
    """자격증명(env 또는 캡처의 성공 로그인에서 자동추출) → (주 세션 A, 보조 세션 B).

    env 자격증명이 없으면 캡처의 성공 로그인에서 자동추출해 재로그인(신선한 세션).
    둘 다 없거나 로그인 검증 실패면 (None, None).
    """
    u1, p1 = os.environ.get("SAST_LOGIN_USER"), os.environ.get("SAST_LOGIN_PASS")
    tmpl = derive_login(exchanges)
    if not tmpl:
        if u1 and p1:
            print("[!] 로그인 요청을 캡처에서 못 찾음 — 캡처에 로그인 트래픽 포함 필요")
        return None, None
    if not (u1 and p1):                          # env 자격증명 없으면 캡처서 자동추출
        dc = derive_credentials(exchanges, tmpl)
        if not dc:
            return None, None
        u1, p1 = dc
        print(f"[*] 캡처의 성공 로그인에서 자격증명 자동추출: user={_mask(u1)} (신선한 세션 재로그인)")
    print(f"[*] 로그인 대상 추론: {tmpl['ex']['method']} {tmpl['ex']['path']} "
          f"(user='{tmpl['user_key']}', pw='{tmpl['pw_key']}')")
    verify_ex = pick_verify_ex(exchanges)
    a = Session(tmpl, u1, p1, verify_ex=verify_ex)
    if not a.ensure():
        print("[!] 계정 A 로그인 검증 실패 — 세션 미확보. (재현율 보호: 비인증 replay 로 조용히 진행하지 않음)")
        return None, None
    b = None
    u2, p2 = os.environ.get("SAST_LOGIN_USER2"), os.environ.get("SAST_LOGIN_PASS2")
    if u2 and p2:
        b = Session(tmpl, u2, p2, verify_ex=verify_ex)
        if b.ensure():
            print("[*] 2계정 모드 — 권한검증(IDOR) 교차확증 활성")
        else:
            print("[!] 계정 B 로그인 검증 실패 — 2계정 IDOR 확증 비활성(A 세션만 사용)"); b = None
    return a, b
