"""P0-2: 로그인 성공을 '실패문구 부재'가 아닌 양성 신호로 검증 (silent auth failure 방지).

로컬 mock HTTP 서버로 실제 로그인 플로우를 태운다(외부 대상 없음).
  - 올바른 PW → 세션 쿠키 발급 + 인증 엔드포인트 접근 가능 → authenticate 성공
  - 틀린 PW  → 인증 엔드포인트가 로그인 화면 반환(차단) → authenticate None
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest
from sast import capture, login

GOOD = {"user": "alice", "pw": "s3cret"}
VALID_SID = "SID-VALID"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _body(self):
        n = int(self.headers.get("content-length", 0))
        return self.rfile.read(n).decode() if n else ""

    def do_POST(self):
        if self.path == "/login":
            b = self._body()
            ok = f"user_id={GOOD['user']}" in b and f"pwd={GOOD['pw']}" in b
            self.send_response(200)
            if ok:
                self.send_header("Set-Cookie", f"SID={VALID_SID}; Path=/")
            self.end_headers()
            self.wfile.write(("ok" if ok else "비밀번호가 맞지 않습니다.").encode("utf-8"))

    def do_GET(self):
        # 인증 필요: 유효 세션 쿠키 없으면 로그인 화면
        if VALID_SID in self.headers.get("Cookie", ""):
            self.send_response(200); self.end_headers(); self.wfile.write(b"DASHBOARD DATA")
        else:
            self.send_response(200); self.end_headers()
            self.wfile.write("login 필요: 로그인 하세요".encode("utf-8"))


@pytest.fixture()
def server():
    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _tmpl(base):
    ex = capture._mk("POST", base + "/login", {"content-type": "application/x-www-form-urlencoded"},
                     "user_id=x&pwd=y", "", "", "", "200", "")
    return {"ex": ex, "user_key": "user_id", "pw_key": "pwd"}


def _verify_ex(base):
    return capture._mk("GET", base + "/mypage", {"cookie": "SID=old"}, "", "", "", "", "200", "")


def test_correct_password_verified(server):
    ck = login.authenticate(_tmpl(server), GOOD["user"], GOOD["pw"], verify_ex=_verify_ex(server))
    assert ck and VALID_SID in ck


def test_wrong_password_returns_none(server):
    ck = login.authenticate(_tmpl(server), GOOD["user"], "WRONG", verify_ex=_verify_ex(server))
    assert ck is None


def test_no_verify_ex_requires_setcookie(server):
    # 올바른 PW 는 Set-Cookie 발급 → 프로브 없어도 성공
    assert login.authenticate(_tmpl(server), GOOD["user"], GOOD["pw"]) is not None
    # 틀린 PW 는 Set-Cookie 없음 → 실패
    assert login.authenticate(_tmpl(server), GOOD["user"], "WRONG") is None
