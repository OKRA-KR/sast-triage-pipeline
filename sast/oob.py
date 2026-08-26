"""OOB(Out-Of-Band) 콜백 리스너 — blind SSRF/XXE/RCE 확증.

payload 에 콜백 URL(http://<내PC>/<토큰>)을 심어 보내고, 대상 서버가 그 주소로
역접속하면 blind 취약점으로 확증한다. 응답에 안 비치는 blind 유형을 잡는 핵심.

이식성: 순수 stdlib(http.server) — Python 만 있으면 어느 PC 에서도 실행, 설치 불필요.
관건은 **대상이 내 PC 로 역접속 가능한 IP** 여야 함:
  - 같은 망: 내 PC LAN IP(자동 감지) · 인터넷/NAT: 공인IP:포트(SAST_OOB_HOST 로 지정)
설정: SAST_OOB_HOST(콜백 host:port) · SAST_OOB_PORT(리슨 포트) · SAST_OOB_WAIT(수집 대기초).
인가 대상 전용.
"""
import http.server, os, socket, threading, time, uuid


def _local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _hit(self):
        tok = self.path.strip("/").split("/")[0].split("?")[0]
        self.server.oob._record(tok, self.path, self.headers.get("User-Agent", ""), self.client_address[0])
        self.send_response(200); self.end_headers()
        try:
            self.wfile.write(b"ok")
        except Exception:
            pass
    do_GET = _hit
    do_POST = _hit


class OOBListener:
    def __init__(self, port=None, callback_host=None):
        self.registry = {}   # token -> (kind, ex, param)
        self.hits = {}       # token -> detail
        port = port if port is not None else int(os.environ.get("SAST_OOB_PORT", "0"))
        self.srv = http.server.HTTPServer(("0.0.0.0", port), _Handler)
        self.srv.oob = self
        self.port = self.srv.server_address[1]
        self.callback_host = callback_host or os.environ.get("SAST_OOB_HOST") or f"{_local_ip()}:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        print(f"[*] OOB 리스너: 0.0.0.0:{self.port} · 콜백주소 http://{self.callback_host}/ "
              f"(대상이 이 주소로 역접속 가능해야 확증)")

    def new(self, kind, ex, param):
        tok = "ok" + uuid.uuid4().hex[:10]
        self.registry[tok] = (kind, ex, param)
        return tok

    def url(self, tok):
        return f"http://{self.callback_host}/{tok}"

    def _record(self, tok, path, ua, src):
        if tok in self.registry:
            self.hits[tok] = {"path": path, "ua": ua, "src": src, "t": time.time()}

    def collect(self, wait=None):
        wait = wait if wait is not None else float(os.environ.get("SAST_OOB_WAIT", "5"))
        if wait:
            time.sleep(wait)
        return {tok: (self.registry[tok], self.hits[tok]) for tok in list(self.hits)}

    def stop(self):
        try:
            self.srv.shutdown(); self.srv.server_close()
        except Exception:
            pass
