"""P0-1: derive_login 이 로그인 요청을 정확히 고르는지 (회원가입/비번변경 오선택 방지)."""
import os
import pytest
from sast import capture, login

GP = "/mnt/c/Users/user/security/gparking"


def _ex(method, url, body="", ct="application/x-www-form-urlencoded"):
    rqh = {"content-type": ct} if body else {}
    return capture._mk(method, url, rqh, body, "", "", "", "200", "")


def test_prefers_login_over_signup_and_pwchange():
    # 회원가입·비번변경이 로그인보다 먼저 등장 — 그래도 로그인을 골라야 함
    exs = [
        _ex("POST", "https://t/api/user/register.php",
            "user_id=a&pwd=1&pwd2=1&email=a@a.com&tel=010&name=n&addr=x"),
        _ex("POST", "https://t/api/user/save.php", "user_id=a&pwd=1&corpName=c&corpTel=010"),
        _ex("POST", "https://t/api/auth/login.php", "mode=login&user_id=a&pwd=1"),
    ]
    t = login.derive_login(exs)
    assert t is not None
    assert t["ex"]["path"] == "/api/auth/login.php"
    assert (t["user_key"], t["pw_key"]) == ("user_id", "pwd")


def test_explicit_url_wins():
    exs = [
        _ex("POST", "https://t/api/auth/login.php", "user_id=a&pwd=1"),
        _ex("POST", "https://t/custom/signon", "userid=a&password=1"),
    ]
    os.environ["SAST_LOGIN_URL"] = "/custom/signon"
    try:
        t = login.derive_login(exs)
        assert t["ex"]["path"] == "/custom/signon"
    finally:
        os.environ.pop("SAST_LOGIN_URL", None)


def test_none_when_no_password_field():
    exs = [_ex("GET", "https://t/api/list?user_id=a")]
    assert login.derive_login(exs) is None


@pytest.mark.skipif(not os.path.exists(GP), reason="gparking 캡처 없음(로컬 전용)")
def test_gparking_real_capture():
    t = login.derive_login(capture.parse(GP))
    assert t["ex"]["path"] == "/api/auth/login.php"
    assert (t["user_key"], t["pw_key"]) == ("user_id", "pwd")
