"""상용 DAST role 보강: SSTI·명령인젝션·SSRF·오픈리다이렉트·CRLF·XXE (stub _send)."""
from urllib.parse import unquote_plus
from sast import capture, replay


def _dec(url, body):
    return unquote_plus(url) + " " + unquote_plus(body or "")


def _ex(method, path, body, ct="application/x-www-form-urlencoded"):
    h = {"content-type": ct}
    return capture._mk(method, "https://t" + path, h, body, "", "", "", "200", "text/html")


def _run(exs, responder):
    orig = replay._send
    replay._send = responder
    replay._req[0] = 0
    try:
        return replay.scan_capture(exs)
    finally:
        replay._send = orig


def test_ssti(monkeypatch):
    ex = _ex("GET", "/page?name=x", "")
    def r(method, url, headers, body, redirect=True):
        return (200, {}, "hi oz49oz") if "7*7" in _dec(url, body) else (200, {}, "hi")
    fs = [f for f in _run([ex], r) if f["category"] == "ssti"]
    assert fs and fs[0]["verdict"] == "true_positive"


def test_command_injection(monkeypatch):
    ex = _ex("GET", "/ping?host=1", "")
    def r(method, url, headers, body, redirect=True):
        d = _dec(url, body)
        return (200, {}, "PING\nuid=33(www-data) gid=33") if any(c in d for c in (";id", "|id", "`id`", "$(id)")) else (200, {}, "ok")
    fs = [f for f in _run([ex], r) if f["category"] == "command-injection"]
    assert fs


def test_ssrf(monkeypatch):
    ex = _ex("GET", "/fetch?url=http://a", "")
    def r(method, url, headers, body, redirect=True):
        return (200, {}, "ami-id: ami-123\ninstance-id: i-1") if "169.254.169.254" in _dec(url, body) else (200, {}, "ok")
    fs = [f for f in _run([ex], r) if f["category"] == "ssrf"]
    assert fs


def test_open_redirect(monkeypatch):
    ex = _ex("GET", "/go?next=/home", "")
    def r(method, url, headers, body, redirect=True):
        if "evil.example" in _dec(url, body) and not redirect:
            return (302, {"location": "https://evil.example/"}, "")
        return (200, {}, "ok")
    fs = [f for f in _run([ex], r) if f["category"] == "open-redirect"]
    assert fs


def test_crlf(monkeypatch):
    ex = _ex("GET", "/set?x=1", "")
    def r(method, url, headers, body, redirect=True):
        if "okrcrlf" in _dec(url, body):
            return (200, {"okrcrlf": "1"}, "ok")     # 서버가 헤더로 반영
        return (200, {}, "ok")
    fs = [f for f in _run([ex], r) if f["category"] == "crlf-injection"]
    assert fs


def test_xxe(monkeypatch):
    ex = _ex("POST", "/api/xml", "<r><a>1</a></r>", ct="application/xml")
    def r(method, url, headers, body, redirect=True):
        if body and "file:///etc/passwd" in body:
            return (200, {}, "parsed: root:x:0:0:root:/root:/bin/bash")
        return (200, {}, "ok")
    fs = [f for f in _run([ex], r) if f["category"] == "xxe"]
    assert fs
