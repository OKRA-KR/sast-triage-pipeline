"""B: camelCase 객체참조 IDOR 이름 판별 + 인증세션 컨텍스트의 _idor_worthy 완화."""
from sast.capture import _is_idor_name, _mk
from sast import replay


def test_camelcase_idor_names():
    for ok in ("carId", "vehicleId", "userId", "orderNo", "userSeq", "video_id", "corp_sn", "id", "pk"):
        assert _is_idor_name(ok), ok
    for no in ("avoid", "email", "name", "password", "payload", "title"):
        assert not _is_idor_name(no), no


def test_idor_worthy_authed_relaxes_cookie():
    # 라우트 다리 교환: ex 에 쿠키 없음. 인증세션 스캔(authed=True)이면 대상, 캡처단독(False)이면 제외
    ex = _mk("GET", "https://h/api/v2/vehicle/1/location", {}, "", "", "", "", "200", "")
    assert replay._idor_worthy(ex, authed=True) is True
    assert replay._idor_worthy(ex, authed=False) is False


def test_idor_worthy_excludes_static_and_writes():
    ex_static = _mk("GET", "https://h/api/app.css", {"cookie": "x"}, "", "", "", "", "200", "")
    assert replay._idor_worthy(ex_static, authed=True) is False
