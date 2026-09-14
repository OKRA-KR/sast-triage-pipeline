"""인증 재크롤 시드 — 로그인 랜딩을 크롤 시드로 넣어 인증 진입점(비인증 base 와 다른)을 도달.

회귀 방지: 비인증 base 가 인증 시 404 인 앱(Spring 등)에서 인증 재크롤이 0건 되던 버그.
"""
from sast import active, login


def test_crawl_visits_seed(monkeypatch):
    base = "http://h.example/App"
    seed = "http://h.example/App/start.mvc"
    fetched = []

    def fake_fetch(url, redirect=True, data=None):
        fetched.append(url)
        if url in (base, seed):
            # start 페이지엔 링크 하나(동일 호스트) — 크롤이 최소 동작
            return 200, {"content-type": "text/html"}, '<a href="/App/x">x</a>'
        return None                       # COMMON_PATHS 등은 미존재 → 스킵

    monkeypatch.setattr(active, "_fetch", fake_fetch)
    exs, npg, nfm, _ = active.crawl_exchanges(base, seeds=[seed])
    assert seed in fetched, "시드 URL 이 크롤돼야 함"
    assert any(e["path"].endswith("/start.mvc") or e["url"].endswith("/start.mvc")
               for e in exs if isinstance(e, dict)) or npg >= 2


def test_crawl_ignores_offhost_seed(monkeypatch):
    base = "http://h.example/App"
    evil = "http://evil.other/steal"
    fetched = []

    def fake_fetch(url, redirect=True, data=None):
        fetched.append(url)
        return (200, {"content-type": "text/html"}, "<html></html>") if url == base else None

    monkeypatch.setattr(active, "_fetch", fake_fetch)
    active.crawl_exchanges(base, seeds=[evil])
    assert evil not in fetched, "다른 호스트 시드는 무시(SSRF/스코프 이탈 방지)"


def test_session_landing_default_none():
    s = login.Session({"ex": {}, "user_key": "u", "pw_key": "p"}, "u", "p")
    assert s.landing is None


def test_session_captures_landing(monkeypatch):
    def fake_auth(tmpl, user, pw, cur=None, verify_ex=None, out=None):
        if out is not None:
            out["landing"] = "http://h.example/App/welcome.mvc"
        return "SID=abc"
    monkeypatch.setattr(login, "authenticate", fake_auth)
    s = login.Session({"ex": {}, "user_key": "u", "pw_key": "p"}, "u", "p")
    assert s.ensure() == "SID=abc"
    assert s.landing == "http://h.example/App/welcome.mvc"
