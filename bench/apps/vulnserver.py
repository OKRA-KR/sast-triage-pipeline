#!/usr/bin/env python3
"""라이브 DAST role 검증용 미니 취약앱 (stdlib only). ⚠ 의도적 취약 — 로컬 검증 전용, 인터넷 노출 금지.

각 엔드포인트가 replay role 을 트리거하도록 입력을 미이스케이프 반사/시뮬한다:
  /search?q=       반사형 XSS + SQLi(오류)      /render?name=  SSTI(산술평가)
  /ping?host=      명령 인젝션(uid= 출력)        /file?path=    LFI(/etc/passwd)
  /redirect?url=   오픈 리다이렉트(302)          /fetch?url=    SSRF(메타데이터)
  POST /save bio=  저장 → /users 에서 미이스케이프 반사(저장형 XSS)
  모든 응답: Origin 반영(CORS 오설정) + Host 반영(Host 헤더 인젝션)
실행: python3 bench/apps/vulnserver.py [port]   (기본 8000)
"""
import re, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

_STORE = {"bio": "정상 소개글"}
HOME = """<html><body><h1>vulnserver</h1>
<a href="/search?q=hello">search</a> <a href="/render?name=world">render</a>
<a href="/ping?host=localhost">ping</a> <a href="/file?path=readme.txt">file</a>
<a href="/redirect?url=/home">redirect</a> <a href="/fetch?url=http://example.com">fetch</a>
<a href="/users">users</a>
<form action="/save" method="post"><input name="bio" value="x"><input type="submit"></form>
</body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        origin = self.headers.get("Origin")
        if origin:                                   # CORS 오설정: 위조 Origin 반영 + 자격증명 허용
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        host = self.headers.get("Host", "")          # Host 헤더 반영(비번재설정 링크)
        body += f'<a href="http://{host}/reset">reset link</a>'
        self.wfile.write(body.encode("utf-8", "replace"))

    def do_GET(self):
        pr = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(pr.query, keep_blank_values=True).items()}
        p = pr.path
        if p in ("/", "/home"):
            return self._send(HOME)
        if p == "/search":
            s = q.get("q", "")
            err = "You have an error in your SQL syntax near ''" if "'" in s else ""
            return self._send(f"<div>Results for {s}</div>{err}")   # 반사형 XSS + SQLi 오류
        if p == "/render":
            n = q.get("name", "")
            for pat in ("{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"):
                n = n.replace(pat, "49")                            # SSTI: 산술 평가 시뮬
            return self._send(f"<p>Hello {n}</p>")
        if p == "/ping":
            h = unquote_plus(q.get("host", ""))
            out = "uid=1000(user) gid=1000(user)" if re.search(r"[;|`]|\$\(", h) else "0% loss"
            return self._send(f"<pre>PING {h}\n{out}</pre>")        # 명령 인젝션
        if p == "/file":
            path = unquote_plus(q.get("path", ""))
            if "etc/passwd" in path:
                return self._send("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin")  # LFI
            return self._send("readme content")
        if p == "/redirect":
            return self._send("", 302, {"Location": q.get("url", "/")})   # 오픈 리다이렉트
        if p == "/fetch":
            u = unquote_plus(q.get("url", ""))
            if "169.254.169.254" in u:
                return self._send("instance-id: i-abc123\nami-id: ami-99\niam/security-credentials/")  # SSRF
            return self._send("fetched ok")
        if p == "/users":
            return self._send(f"<table><tr><td>{_STORE['bio']}</td></tr></table>")   # 저장형 XSS 반사
        return self._send("<h1>404</h1>", 404)

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        q = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
        if urlparse(self.path).path == "/save":
            _STORE["bio"] = q.get("bio", "")           # 저장(→ /users 에서 미이스케이프 반사)
            return self._send("saved")
        return self._send("ok")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"[vulnserver] http://127.0.0.1:{port}/  (의도적 취약 — 로컬 검증 전용)")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
