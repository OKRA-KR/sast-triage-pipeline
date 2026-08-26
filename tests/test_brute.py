"""로그인 무차별 대입 — 약한자격증명 탐지 / 락아웃 감지 / 방어부재. (stub _send_raw)"""
import re
from urllib.parse import unquote_plus
from sast import capture, login


def _login_ex():
    return capture._mk("POST", "https://t/api/auth/login.php",
                       {"content-type": "application/x-www-form-urlencoded"},
                       "mode=login&user_id=glnt&pwd=x", "", "", "", "200", "")


def _pw(body, url):
    m = re.search(r"pwd=([^&]*)", (body or "") + "&" + url)
    return unquote_plus(m.group(1)) if m else ""


def _patch(monkeypatch, fn):
    monkeypatch.setattr(login, "_send_raw", fn)


def test_weak_credential_found(monkeypatch):
    def send(method, url, headers, body, cookie=None):
        pw = _pw(body, url)
        return (200, {}, "success#1") if pw == "1234" else (200, {}, "비밀번호가 맞지 않습니다.")
    _patch(monkeypatch, send)
    fs = login.brute_force([_login_ex()], "glnt")
    assert any(f["category"] == "broken-auth" and "약한 자격증명" in f["message"] for f in fs)
    # 실제 비번은 마스킹
    assert all("1234" not in f["evidence"] for f in fs)


def test_no_lockout_flagged(monkeypatch):
    def send(method, url, headers, body, cookie=None):
        return (200, {}, "비밀번호가 맞지 않습니다.")     # 항상 실패, 차단 없음
    _patch(monkeypatch, send)
    fs = login.brute_force([_login_ex()], "glnt")
    assert any(f["category"] == "missing-anti-automation" for f in fs)


def test_lockout_no_finding(monkeypatch):
    calls = {"n": 0}
    def send(method, url, headers, body, cookie=None):
        calls["n"] += 1
        if calls["n"] >= 3:
            return (403, {}, "너무 많은 시도")           # 락아웃
        return (200, {}, "비밀번호가 맞지 않습니다.")
    _patch(monkeypatch, send)
    fs = login.brute_force([_login_ex()], "glnt")
    assert fs == []      # 방어 동작(락아웃) → finding 없음
