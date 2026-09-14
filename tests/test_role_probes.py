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
    # 무세션에도 200+데이터 → 후보로 surfacing. 단 응답만으론 공개/보호대상 구분 불가라
    # 하드 확증(true_positive/동적확증)은 하지 않고 검토대상으로 남긴다(실사이트 대량 오탐 방지).
    ma = [f for f in fs if f["category"] == "missing-auth"]
    assert ma, "무인증 200 이면 후보로 surfacing 되어야 함"
    assert all(f["verdict"] != "true_positive" for f in ma), "응답만으론 확증 불가 → 하드 확증 금지"
    assert all((f.get("dynamic") or {}).get("status") != "confirmed" for f in ma), "동적확증 카운트 금지"


def test_static_asset_not_missing_auth():
    # 정적 리소스(css/js/img)는 무인증 200 이 정상 — missing-auth 로 잡으면 안 됨(검토버킷 노이즈)
    exs = [_ex("GET", "/css/main.css", ""), _ex("GET", "/js/libs/require.min.js", ""),
           _ex("GET", "/css/img/favicon.ico", "")]

    def responder(method, url, headers, body):
        return 200, {"content-type": "text/css"}, "body{color:red}" + "z" * 300
    fs = _run(exs, responder)
    assert not [f for f in fs if f["category"] == "missing-auth"], \
        "정적 리소스는 무인증 스윕에서 제외돼야 함"


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
