"""C: 실객체 ID 하베스팅·치환 BOLA — path 자리표시를 A의 진짜 id 로 바꿔 2계정 교차검증."""
from sast import replay
from sast.capture import _mk


def test_id_shaped():
    assert replay._id_shaped("10")
    assert replay._id_shaped("a1b2c3d4-1111-2222-3333-444455556666")   # UUID
    assert not replay._id_shaped("hello")
    assert not replay._id_shaped("12345678901234")                     # 13자리 초과


def test_swap_ph_path_only():
    # path 의 '1' 세그먼트만 치환, 쿼리는 보존
    assert replay._swap_ph("http://h/api/videos/1?x=1", "10") == "http://h/api/videos/10?x=1"
    assert replay._swap_ph("http://h/api/vehicle/1/location", "u-9") == "http://h/api/vehicle/u-9/location"
    assert replay._swap_ph("http://h/api/list", "10") == "http://h/api/list"   # 자리표시 없음 → 불변


def test_bola_real_id_confirms(monkeypatch):
    # A 가 실객체 10 소유(응답에 고유토큰), B 세션이 같은 URL 로 A 토큰 획득 → BOLA 확정
    ex = _mk("GET", "https://h/api/v2/user/videos/1", {}, "", "", "", "", "200", "")

    class S:
        def __init__(self, c): self.cookie = c; self.label = c

    def fake_send(method, url, headers, body):
        if url.endswith("/videos/10"):
            return 200, {}, '{"id":10,"email":"owner_a@test.com","title":"A video"}' + " " * 60
        return None                                          # 다른 id 는 A 미소유
    monkeypatch.setattr(replay, "_send", fake_send)
    found = []
    replay._bola_real_id(ex, S("Bearer A"), S("Bearer B"), ["10"], lambda f: found.append(f))
    assert found and found[0]["category"] == "idor" and found[0]["verdict"] == "true_positive"
    assert "10" in found[0]["evidence"]


def test_bola_real_id_no_finding_when_isolated(monkeypatch):
    ex = _mk("GET", "https://h/api/v2/user/videos/1", {}, "", "", "", "", "200", "")

    class S:
        def __init__(self, c): self.cookie = c; self.label = c

    def fake_send(method, url, headers, body):
        if "Bearer A" in headers.get("Authorization", "") and url.endswith("/videos/10"):
            return 200, {}, '{"id":10,"email":"owner_a@test.com"}' + " " * 60
        return 403, {}, ""                                   # B 는 차단(정상 격리)
    monkeypatch.setattr(replay, "_send", fake_send)
    found = []
    replay._bola_real_id(ex, S("Bearer A"), S("Bearer B"), ["10"], lambda f: found.append(f))
    assert not found                                         # 격리 정상 → BOLA 없음
