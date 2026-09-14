"""A: 패시브 recon Tier 0 — DoH 리졸버 + Wayback CDX 엔드포인트 (네트워크 목).

외부통신은 전부 monkeypatch 로 대체 — 테스트는 오프라인에서 돈다.
"""
import io, json
import urllib.request
from sast import recon


class _Resp(io.BytesIO):
    """urlopen 컨텍스트매니저 흉내 — with 문 + .read()."""
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _fake_urlopen(payload):
    data = json.dumps(payload).encode()

    def _open(req, *a, **k):
        return _Resp(data)
    return _open


# ── DoH 파싱 ──────────────────────────────────────────────────────────
def test_doh_noerror_returns_ips(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        _fake_urlopen({"Status": 0, "Answer": [
                            {"type": 1, "data": "1.2.3.4"},
                            {"type": 5, "data": "cname.tgt."},   # CNAME 은 제외
                            {"type": 1, "data": "5.6.7.8"}]}))
    assert recon._doh("api.example.com") == ["1.2.3.4", "5.6.7.8"]


def test_doh_nxdomain_is_definitive_empty(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen({"Status": 3}))
    assert recon._doh("nope.example.com") == []      # None 아님 = 폴백 안 함


def test_resolve_prefers_doh_then_falls_back(monkeypatch):
    # DoH 불가(None) 로 만들고 시스템 리졸버 폴백 확인
    monkeypatch.setattr(recon, "_doh", lambda h, rtype="A": None)
    monkeypatch.setattr(recon, "_resolve", lambda h: ["9.9.9.9"])
    assert recon.resolve("h", use_doh=True) == ["9.9.9.9"]
    # DoH 성공 시 시스템 리졸버 안 씀
    monkeypatch.setattr(recon, "_doh", lambda h, rtype="A": ["1.1.1.1"])
    monkeypatch.setattr(recon, "_resolve", lambda h: (_ for _ in ()).throw(AssertionError("호출 금지")))
    assert recon.resolve("h", use_doh=True) == ["1.1.1.1"]


# ── Wayback CDX ───────────────────────────────────────────────────────
def test_wayback_hosts_and_endpoints(monkeypatch):
    recon._WB_CACHE.clear()
    rows = [["original"],                                  # 헤더(스킵됨)
            ["https://api.example.com/v1/user?id=7"],
            ["https://api.example.com/v1/user?id=8"],       # 같은 엔드포인트, param 병합
            ["https://admin.example.com/login"],
            ["https://evil.notexample.com/x"]]              # 도메인 밖 → hosts 제외
    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen(rows))

    hosts = recon._wayback_hosts("example.com")
    assert hosts == {"api.example.com", "admin.example.com"}

    urls = recon._wayback_urls("example.com")               # 캐시 재사용(재질의 없음)
    inv = recon.wayback_endpoints(urls)
    by_path = {e["path"]: e for e in inv}
    assert "api.example.com/v1/user" in by_path
    assert by_path["api.example.com/v1/user"]["count"] == 2  # id=7,8 병합
    assert "id" in by_path["api.example.com/v1/user"]["params"]
    assert by_path["api.example.com/v1/user"]["method"] == "GET"
    # notexample.com 도 URL 로는 남지만(아카이브가 준 것) 엔드포인트 host 로 구분됨
    assert "admin.example.com/login" in by_path
