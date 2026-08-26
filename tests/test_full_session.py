"""--full 세션 확보(working_session) — 계정 못 찾으면 ok=False (호출측이 종료)."""
import os
from sast import capture, login


def _authed_get():
    return capture._mk("GET", "https://t/api/user", {"cookie": "PHPSESSID=A"}, "", "", "", "", "200", "")


def _clear(monkeypatch):
    for k in ("SAST_LOGIN_USER", "SAST_LOGIN_PASS", "SAST_HTTP_COOKIE"):
        monkeypatch.delenv(k, raising=False)


def test_creds_success(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("SAST_LOGIN_USER", "u"); monkeypatch.setenv("SAST_LOGIN_PASS", "p")
    monkeypatch.setattr(login, "build_sessions", lambda exs: ("SESSA", None))
    ok, a, b = login.working_session([])
    assert ok is True and a == "SESSA"


def test_creds_fail_terminates(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("SAST_LOGIN_USER", "u"); monkeypatch.setenv("SAST_LOGIN_PASS", "bad")
    monkeypatch.setattr(login, "build_sessions", lambda exs: (None, None))
    ok, a, b = login.working_session([])
    assert ok is False           # 로그인 실패 → 종료 신호


def test_valid_cookie(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("SAST_HTTP_COOKIE", "PHPSESSID=A")
    monkeypatch.setattr(login, "_send_raw", lambda m, u, h, b, cookie=None: (200, {}, "DASHBOARD data"))
    ok, a, b = login.working_session([_authed_get()])
    assert ok is True


def test_invalid_cookie_terminates(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("SAST_HTTP_COOKIE", "PHPSESSID=stale")
    monkeypatch.setattr(login, "_send_raw", lambda m, u, h, b, cookie=None: (200, {}, "로그인 하세요"))
    ok, a, b = login.working_session([_authed_get()])
    assert ok is False           # 쿠키 무효 → 종료


def test_no_account_terminates(monkeypatch):
    _clear(monkeypatch)
    ok, a, b = login.working_session([_authed_get()])
    assert ok is False           # 자격증명·쿠키 둘 다 없음 → 종료
