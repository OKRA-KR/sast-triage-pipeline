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
from .capture import _AUTHFAIL, _body_params

_USER_KEYS = re.compile(r"^(user_?id|userid|user_?nm|username|login_?id|mb_id|account|userno|memid|email|id|user)$", re.I)
_PW_KEYS = re.compile(r"^(pwd|passwd|password|user_?pw|passwrd|upw|pw|pass)$", re.I)
TIMEOUT = 10


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


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


def _send_raw(method, url, headers, body, cookie=None):
    h = {k: v for k, v in headers.items() if k not in _DROP}
    if cookie:
        h["Cookie"] = cookie
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


def authenticate(template, user, pw, cur_cookie=None, verify_ex=None):
    """로그인 요청 전송 → **양성 성공 검증** 통과 시 세션 쿠키 반환, 아니면 None.

    실패 문구 부재만으로 성공 판정하지 않는다(silent auth failure 방지):
    verify_ex(인증 필요 엔드포인트)를 새 세션으로 프로브해 차단이 아니어야 성공.
    프로브 대상이 없으면 Set-Cookie 로 세션이 새로 발급된 경우만 성공 인정.
    """
    ex = template["ex"]
    pr = urlparse(ex["url"])
    ct = (ex["req_headers"].get("content-type") or "").lower()
    # 요청 헤더(쿠키만 교체 가능), user/pw 치환
    hdr = {k: v for k, v in ex["req_headers"].items()
           if k not in ("content-length", "host", "connection", "accept-encoding")}
    if cur_cookie:
        hdr["Cookie"] = cur_cookie
    def _sub(pairs):
        d = dict(pairs)
        d[template["user_key"]] = user; d[template["pw_key"]] = pw
        return urlencode(d)
    body = None
    if ex["method"] == "POST":
        if "application/json" in ct:
            import json as _j
            try:
                obj = _j.loads(ex["req_body"] or "{}")
            except Exception:
                obj = {}
            obj[template["user_key"]] = user; obj[template["pw_key"]] = pw
            body = _j.dumps(obj)
        else:
            body = _sub(parse_qsl(ex["req_body"] or "", keep_blank_values=True))
        url = ex["url"]
    else:  # GET 로그인
        url = pr._replace(query=_sub(parse_qsl(pr.query, keep_blank_values=True))).geturl()
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=ex["method"],
                                 headers={k: v for k, v in hdr.items() if k})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            rb = r.read(20000).decode("utf-8", "replace")
            rh = {k.lower(): v for k, v in r.headers.items()}
    except urllib.error.HTTPError as e:
        rb = e.read(20000).decode("utf-8", "replace") if hasattr(e, "read") else ""
        rh = {k.lower(): v for k, v in (e.headers or {}).items()}
    except Exception as ex_e:
        print(f"[!] 로그인 요청 실패: {str(ex_e)[:100]}"); return None
    if _AUTHFAIL.search(rb):
        print(f"[!] 로그인 실패(자격증명 오류 응답): user={_mask(user)}"); return None
    new_cookie = _cookie_from(rh)
    post_cookie = new_cookie or cur_cookie
    # ── 양성 성공 검증 ──
    if verify_ex is not None:
        pr = _send_raw(verify_ex["method"], verify_ex["url"], verify_ex["req_headers"], None, post_cookie)
        if _blocked(pr):
            print(f"[!] 로그인 검증 실패 — 세션 미확보(인증 엔드포인트 차단): user={_mask(user)}")
            return None
        print(f"[*] 로그인 성공(검증됨): user={_mask(user)} · 세션 {'갱신' if new_cookie else '유지'}")
        return post_cookie
    if new_cookie:
        print(f"[*] 로그인 성공(세션 발급): user={_mask(user)}")
        return new_cookie
    print(f"[!] 로그인 검증 불가 — Set-Cookie 없음·프로브 대상 없음: user={_mask(user)} → 실패 처리")
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


def build_sessions(exchanges):
    """환경변수 자격증명 → (주 세션 A, 보조 세션 B). 캡처에서 로그인 추론.

    자격증명 없으면 (None, None) — 기존 캡처 쿠키로 진행.
    로그인 검증 실패 시에도 (None, None) 반환 + 경고(비인증으로 조용히 진행 금지 — 호출측 판단).
    """
    u1, p1 = os.environ.get("SAST_LOGIN_USER"), os.environ.get("SAST_LOGIN_PASS")
    if not (u1 and p1):
        return None, None
    tmpl = derive_login(exchanges)
    if not tmpl:
        print("[!] 로그인 요청을 캡처에서 못 찾음 — 캡처에 로그인 트래픽 포함 필요"); return None, None
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
