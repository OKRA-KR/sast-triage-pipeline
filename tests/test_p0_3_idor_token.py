"""P0-3: 2계정 IDOR 확정은 'A 고유 토큰이 B 응답에 존재'해야만 (길이유사 오탐 차단)."""
from sast import capture, replay


class _Sess:
    def __init__(self, label, cookie):
        self.label, self.cookie = label, cookie
    def reauth(self):
        return self.cookie


def _ex(path, body):
    return capture._mk("POST", "https://t" + path,
                       {"content-type": "application/x-www-form-urlencoded", "cookie": "SID=A"},
                       body, "", "", "", "200", "text/html")


def _run(exs, responder):
    replay._send = responder
    replay._req[0] = 0
    a, b = _Sess("A***", "SID=A"), _Sess("B***", "SID=B")
    return replay.scan_capture(exs, a, b)


def test_confirmed_when_A_token_in_B_response():
    # corp_sn=1001 인 A 요청. B 응답에 A 고유 이메일이 들어오면 확정.
    ex = _ex("/api/search/pgpayment.php", "corp_sn=1001&type=all")
    A_EMAIL = "alice.corp@example.com"
    def responder(method, url, headers, body):
        # A 세션/B 세션 모두 corp_sn=1001 의 A 데이터(이메일)를 반환 → 접근통제 실패
        return 200, {}, f"<rows>{A_EMAIL} 1001 payment data " + "y" * 800 + "</rows>"
    fs = [f for f in _run([ex], responder) if f["category"] == "idor"]
    tp = [f for f in fs if f["verdict"] == "true_positive"]
    assert tp, "A 토큰이 B 응답에 있으면 IDOR 확정이어야 함"
    assert "1001" in tp[0]["evidence"] or A_EMAIL in tp[0]["evidence"]


def test_not_confirmed_for_session_determined_endpoint():
    # 세션결정형: id 무시하고 각 세션이 '자기' 이메일을 반환 → A 토큰이 B 응답에 없음 → 확정 아님
    ex = _ex("/api/search/pgpayment.php", "corp_sn=1001&type=all")
    def responder(method, url, headers, body):
        who = "alice@ex.com" if "SID=A" in headers.get("Cookie", "") else "bob@ex.com"
        return 200, {}, f"<rows>{who} own data " + "y" * 800 + "</rows>"
    fs = [f for f in _run([ex], responder) if f["category"] == "idor"]
    assert not any(f["verdict"] == "true_positive" for f in fs), "세션결정형은 확정이면 안 됨"
    # 접근은 되므로 needs_review 후보로만 남을 수 있음
    assert all(f["verdict"] != "true_positive" for f in fs)


def test_skipped_when_no_object_ref_param():
    # 객체참조 파라미터가 없으면 2계정 확정 시도 자체를 안 함
    ex = _ex("/api/profile.php", "tab=info")
    def responder(method, url, headers, body):
        return 200, {}, "<rows>" + "y" * 800 + "</rows>"
    fs = [f for f in _run([ex], responder) if f["category"] == "idor" and "계정간" in f["message"]]
    assert not fs, "객체참조 파라미터 없으면 2계정 IDOR 확정 대상 아님"
