"""로그인 자격증명 자동추출 — 캡처의 성공 로그인에서 재로그인(env 변수 없이도 동작)."""
from sast import capture, login


def _login_ex(user, pw, resp):
    return capture._mk("POST", "https://t/api/auth/login.php",
                       {"content-type": "application/x-www-form-urlencoded"},
                       f"mode=login&user_id={user}&pwd={pw}", "", "", resp, "200", "text/plain")


def test_derive_credentials_from_success():
    exs = [
        _login_ex("glnt", "wrong", "비밀번호가 맞지 않습니다."),   # 실패
        _login_ex("glnt", "gl1357", "success#1"),                 # 성공 ← 이걸 추출
    ]
    t = login.derive_login(exs)
    dc = login.derive_credentials(exs, t)
    assert dc == ("glnt", "gl1357")


def test_no_success_no_creds():
    exs = [_login_ex("glnt", "wrong", "비밀번호가 맞지 않습니다.")]
    t = login.derive_login(exs)
    assert login.derive_credentials(exs, t) is None


def test_build_sessions_auto_login(monkeypatch):
    # env 자격증명 없이도 캡처 성공로그인으로 세션 확보
    monkeypatch.delenv("SAST_LOGIN_USER", raising=False)
    monkeypatch.delenv("SAST_LOGIN_PASS", raising=False)
    monkeypatch.setattr(login, "authenticate",
                        lambda tmpl, user, pw, cur=None, verify_ex=None: "PHPSESSID=fresh")
    exs = [_login_ex("glnt", "gl1357", "success#1")]
    a, b = login.build_sessions(exs)
    assert a is not None and a.cookie == "PHPSESSID=fresh"


def test_working_session_uses_auto_creds(monkeypatch):
    monkeypatch.delenv("SAST_LOGIN_USER", raising=False)
    monkeypatch.delenv("SAST_LOGIN_PASS", raising=False)
    monkeypatch.delenv("SAST_HTTP_COOKIE", raising=False)
    monkeypatch.setattr(login, "authenticate",
                        lambda tmpl, user, pw, cur=None, verify_ex=None: "PHPSESSID=fresh")
    exs = [_login_ex("glnt", "gl1357", "success#1")]
    ok, a, b = login.working_session(exs)
    assert ok is True and a.cookie == "PHPSESSID=fresh"
