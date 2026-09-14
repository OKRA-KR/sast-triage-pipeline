"""_extract_js_endpoints — 상대경로 resolve 회귀. bare 상대(service/x.mvc)가 JS 디렉터리에
붙어 쓰레기 경로 나오던 것 차단(그런 서버 라우트는 routes.py 담당)."""
from sast import active


def test_bare_relative_not_fabricated():
    # 프레임워크 컨텍스트상대 AJAX — JS 파일 디렉터리에 붙이면 안 됨(쓰레기 경로 방지)
    js = 'fetch("service/restartlesson.mvc")'
    eps = active._extract_js_endpoints(js, "http://h", "h",
                                       "http://h/app/js/goatApp/controller/x.js")
    assert not any("goatApp/controller/service" in e for e in eps), \
        "bare 상대를 JS 디렉터리에 붙인 쓰레기 경로가 없어야 함"


def test_absolute_and_explicit_relative_kept():
    js = 'fetch("/api/users"); axios.get("./detail"); fetch("../list")'
    eps = active._extract_js_endpoints(js, "http://h", "h", "http://h/app/page")
    assert "http://h/api/users" in eps            # 절대경로
    assert any(e.endswith("/app/detail") for e in eps)   # ./detail
    assert any(e.endswith("/list") for e in eps)         # ../list
