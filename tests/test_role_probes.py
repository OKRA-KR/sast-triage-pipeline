"""XSS(저장형)·인증부재 role 프로브 검증 (stub _send, 네트워크 없음)."""
from sast import capture, replay


def _ex(method, path, body, cookie=True):
    h = {"content-type": "application/x-www-form-urlencoded"}
    if cookie:
        h["cookie"] = "PHPSESSID=A"
    return capture._mk(method, "https://t" + path, h, body, "", "", "", "200", "text/html")


def _run(exs, responder):
    orig = replay._send
    replay._send = responder
    replay._req[0] = 0
    try:
        return replay.scan_capture(exs)
    finally:
        replay._send = orig


def test_missing_auth_detected():
    ex = _ex("POST", "/api/user/save.php", "corpNo=1&corpName=x&pwd=p")

    def responder(method, url, headers, body):
        # 쿠키 유무와 무관하게 항상 success + 데이터 → 인증 부재
        return 200, {}, "success " + "y" * 300
    fs = _run([ex], responder)
    assert any(f["category"] == "missing-auth" and f["verdict"] == "true_positive" for f in fs), \
        "무세션에도 처리되면 인증부재로 잡아야 함"


def test_auth_enforced_not_flagged():
    ex = _ex("POST", "/api/user/save.php", "corpNo=1&corpName=x&pwd=p")

    def responder(method, url, headers, body):
        if "PHPSESSID" in headers.get("Cookie", "") or "PHPSESSID" in headers.get("cookie", ""):
            return 200, {}, "success " + "y" * 300
        return 200, {}, "login 필요: 로그인 하세요"     # 무세션은 로그인 화면(차단)
    fs = _run([ex], responder)
    assert not any(f["category"] == "missing-auth" for f in fs), "인증 강제되면 미탐이어야 함"


def test_stored_xss_detected():
    # save(쓰기)에 마커 저장 → /user(읽기) 재조회서 미이스케이프 반사
    save = _ex("POST", "/api/user/save.php", "corpNo=1&corpManager=glnt&pwd=p")
    view = _ex("GET", "/user", "")
    stored = {"v": ""}

    def responder(method, url, headers, body):
        if "save.php" in url or "save.php" in (body or ""):
            if replay._STORED_MARK in (body or ""):
                stored["v"] = replay._STORED_PAYLOAD       # 저장됨
            return 200, {}, "success"
        if "/user" in url:
            return 200, {}, '<input value="' + stored["v"] + '">'   # 미이스케이프 반사
        return 200, {}, "y" * 200
    fs = _run([save, view], responder)
    assert any(f["category"] == "xss" and "저장형" in f["message"] for f in fs), "저장형 XSS 확정돼야 함"
