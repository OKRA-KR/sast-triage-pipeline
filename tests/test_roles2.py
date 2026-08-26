"""NoSQL·CORS·Host헤더 인젝션 role (stub _send)."""
from urllib.parse import unquote_plus
from sast import capture, replay


def _ex(method, path, body, ct="application/x-www-form-urlencoded"):
    return capture._mk(method, "https://t" + path, {"content-type": ct}, body, "", "", "", "200", "text/html")


def _run(exs, responder):
    orig = replay._send
    replay._send = responder
    replay._req[0] = 0
    try:
        return replay.scan_capture(exs)
    finally:
        replay._send = orig


def test_nosql_error(monkeypatch):
    ex = _ex("POST", "/api/login", "user=a&pwd=b")
    def r(method, url, headers, body, redirect=True):
        d = unquote_plus(url + " " + (body or ""))
        if any(t in d for t in ("$gt", "[$ne]", "'", '"')):
            return (200, {}, "MongoError: bad query")
        return (200, {}, "ok")
    fs = [f for f in _run([ex], r) if f["category"] == "nosql-injection"]
    assert fs and fs[0]["verdict"] == "true_positive"


def test_cors_reflect_origin(monkeypatch):
    ex = _ex("GET", "/api/data", "")
    def r(method, url, headers, body, redirect=True):
        if headers.get("Origin") == "https://evil.example":
            return (200, {"access-control-allow-origin": "https://evil.example",
                          "access-control-allow-credentials": "true"}, "data")
        return (200, {}, "data")
    fs = [f for f in _run([ex], r) if f["category"] == "cors-misconfig"]
    assert fs


def test_host_header_injection(monkeypatch):
    ex = _ex("GET", "/reset", "")
    def r(method, url, headers, body, redirect=True):
        if headers.get("Host") == "evil.example" or headers.get("X-Forwarded-Host") == "evil.example":
            return (200, {}, '<a href="https://evil.example/reset?t=1">reset</a>')
        return (200, {}, "home")
    fs = [f for f in _run([ex], r) if f["category"] == "host-header-injection"]
    assert fs
