"""OOB 리스너 + blind 확증 — 대상이 콜백하면 finding 생성 (로컬 루프백)."""
import time
import urllib.request
from sast import capture, replay, oob as oobmod


def test_oob_listener_records_and_confirms(monkeypatch):
    listener = oobmod.OOBListener(callback_host=None)   # 127.0.0.1:port 자동
    # 콜백 host 를 루프백으로 고정(테스트 결정성)
    listener.callback_host = f"127.0.0.1:{listener.port}"
    monkeypatch.setenv("SAST_OOB_WAIT", "1")

    # 취약 서버 흉내: fetch 파라미터의 URL 로 서버가 '역접속'(=OOB 콜백)한다
    def fake_send(method, url, headers, body, redirect=True):
        from urllib.parse import unquote_plus
        blob = unquote_plus(url + " " + (body or ""))
        m = None
        import re
        m = re.search(r"http://127\.0\.0\.1:\d+/(ok\w+)", blob)
        if m:                                            # 서버가 콜백 URL 로 역접속
            try:
                urllib.request.urlopen(listener.url(m.group(1)), timeout=2).read()
            except Exception:
                pass
        return 200, {}, "ok"
    monkeypatch.setattr(replay, "_send", fake_send)
    replay._req[0] = 0

    ex = capture._mk("GET", "https://t/fetch?url=http://x", {}, "", "", "", "", "200", "")
    fs = replay.scan_capture([ex], oob=listener)
    listener.stop()
    cats = {f["category"] for f in fs}
    assert "ssrf" in cats or "command-injection" in cats     # blind 콜백으로 확증됨
    assert any("OOB 콜백 수신" in f["evidence"] for f in fs)
