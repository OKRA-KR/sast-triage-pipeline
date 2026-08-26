"""CSRF 토큰 로그인 + JSON/Bearer 로그인 (mock HTTP 서버)."""
import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest
from sast import capture, login

CSRF_TOKEN = "tok-abc-123"
COOKIE = "SID=ok"
BEARER = "eyJhbGrealbearertoken0123456789"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("content-length", 0))
        return self.rfile.read(n).decode() if n else ""

    def do_GET(self):
        if self.path == "/login":                       # CSRF 폼 페이지
            self.send_response(200); self.end_headers()
            self.wfile.write(f'<form><input name="_csrf" value="{CSRF_TOKEN}"></form>'.encode())
        elif self.path == "/home":                      # 인증 필요(쿠키)
            ok = COOKIE in self.headers.get("Cookie", "")
            self.send_response(200); self.end_headers()
            self.wfile.write(b"DASH" if ok else "로그인 하세요".encode())
        elif self.path == "/api/me":                    # 인증 필요(Bearer)
            ok = BEARER in self.headers.get("Authorization", "")
            self.send_response(200); self.end_headers()
            self.wfile.write(b"PROFILE" if ok else "로그인 하세요".encode())
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        b = self._body()
        if self.path == "/login":                       # CSRF 검증 로그인
            self.send_response(200)
            if f"_csrf={CSRF_TOKEN}" in b and "pwd=s3cret" in b:
                self.send_header("Set-Cookie", COOKIE + "; Path=/")
            self.end_headers(); self.wfile.write(b"ok")
        elif self.path == "/api/login":                 # JSON 로그인 → bearer
            try:
                d = json.loads(b)
            except Exception:
                d = {}
            self.send_response(200); self.end_headers()
            if d.get("pwd") == "s3cret":
                self.wfile.write(json.dumps({"access_token": BEARER}).encode())
            else:
                self.wfile.write(json.dumps({"error": "invalid credentials"}).encode())


@pytest.fixture()
def server():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_csrf_login(server):
    ex = capture._mk("POST", server + "/login",
                     {"content-type": "application/x-www-form-urlencoded", "referer": server + "/login"},
                     "user_id=bob&pwd=x&_csrf=STALE", "", "", "", "200", "")
    tmpl = {"ex": ex, "user_key": "user_id", "pw_key": "pwd"}
    verify = capture._mk("GET", server + "/home", {"cookie": "SID=x"}, "", "", "", "", "200", "")
    cred = login.authenticate(tmpl, "bob", "s3cret", verify_ex=verify)
    assert cred and COOKIE in cred          # 신선한 CSRF 토큰으로 로그인 성공


def test_json_bearer_login(server):
    ex = capture._mk("POST", server + "/api/login", {"content-type": "application/json"},
                     '{"user_id":"bob","pwd":"x"}', "", "", "", "200", "")
    tmpl = {"ex": ex, "user_key": "user_id", "pw_key": "pwd"}
    verify = capture._mk("GET", server + "/api/me", {"authorization": "Bearer old"}, "", "", "", "", "200", "")
    cred = login.authenticate(tmpl, "bob", "s3cret", verify_ex=verify)
    assert cred and cred.startswith("Bearer ") and BEARER in cred


def test_json_wrong_pw_fails(server):
    ex = capture._mk("POST", server + "/api/login", {"content-type": "application/json"},
                     '{"user_id":"bob","pwd":"x"}', "", "", "", "200", "")
    tmpl = {"ex": ex, "user_key": "user_id", "pw_key": "pwd"}
    verify = capture._mk("GET", server + "/api/me", {"authorization": "Bearer old"}, "", "", "", "", "200", "")
    assert login.authenticate(tmpl, "bob", "WRONG", verify_ex=verify) is None
