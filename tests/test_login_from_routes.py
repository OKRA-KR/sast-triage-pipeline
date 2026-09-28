"""라우트 다리 기반 로그인 템플릿 생성 — JSON-API/SPA 인증(크롤에 로그인 없을 때)."""
import os
import pytest
from sast import login


ROUTES = [
    {"method": "POST", "path": "/identity/api/auth/login", "params": [], "write": True, "destructive": False},
    {"method": "POST", "path": "/identity/api/auth/signup", "params": [], "write": True, "destructive": False},
    {"method": "POST", "path": "/identity/api/auth/forget-password", "params": [], "write": True, "destructive": True},
    {"method": "GET", "path": "/identity/api/v2/user/dashboard", "params": [], "write": False, "destructive": False},
]


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SAST_LOGIN_FIELDS", "SAST_LOGIN_JSON", "SAST_LOGIN_URL"):
        monkeypatch.delenv(k, raising=False)


def test_picks_login_route_not_signup():
    cands = login.login_templates_from_routes(ROUTES, "http://h:8888")
    assert cands, "로그인 후보가 나와야 함"
    urls = {c["ex"]["url"] for c in cands}
    assert "http://h:8888/identity/api/auth/login" in urls
    assert all("signup" not in u and "forget" not in u for u in urls), "회원가입/비번찾기는 제외"


def test_env_fields_override(monkeypatch):
    monkeypatch.setenv("SAST_LOGIN_FIELDS", "email,password")
    monkeypatch.setenv("SAST_LOGIN_JSON", "1")
    cands = login.login_templates_from_routes(ROUTES, "http://h:8888")
    assert cands and (cands[0]["user_key"], cands[0]["pw_key"]) == ("email", "password")
    # SAST_LOGIN_JSON → JSON 바디 하나만
    assert all("application/json" in c["ex"]["req_headers"].get("content-type", "") for c in cands)


def test_no_login_route_returns_empty():
    routes = [{"method": "GET", "path": "/api/list", "params": []},
              {"method": "POST", "path": "/api/order/create", "params": []}]
    assert login.login_templates_from_routes(routes, "http://h") == []


def test_needs_routes_and_base():
    assert login.login_templates_from_routes(None, "http://h") == []
    assert login.login_templates_from_routes(ROUTES, None) == []
