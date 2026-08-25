"""P1-2: secrets_engine 순수함수 — 체크섬/구조검증/엔트로피. 합성 가짜값만 사용."""
import base64, json
from sast.engines import secrets_engine as se


def _valid_rrn(prefix12):
    """임의 12자리에 유효 체크섬 붙여 합성 주민번호 생성(실데이터 아님)."""
    d = [int(c) for c in prefix12]
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    chk = (11 - (sum(d[i] * w[i] for i in range(12)) % 11)) % 10
    return prefix12 + str(chk)


def test_rrn_checksum():
    good = _valid_rrn("900101123456")          # 유효 월/일 + 유효 체크섬(합성)
    assert se._rrn(good) is True
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert se._rrn(bad) is False
    assert se._rrn("900133123456" + "0") is False  # 잘못된 일(33)


def test_luhn():
    assert se._luhn("4111111111111111") is True    # 테스트 Visa(합성)
    assert se._luhn("4111111111111112") is False
    assert se._luhn("1234") is False                 # 너무 짧음


def test_valid_jwt():
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    pay = base64.urlsafe_b64encode(json.dumps({"sub": "x"}).encode()).decode().rstrip("=")
    assert se._valid_jwt(f"{hdr}.{pay}.sigsigsig") is True
    assert se._valid_jwt("eyJx.eyJy.zzz") is False   # 헤더가 JSON 아님
    assert se._valid_jwt("only.two") is False


def test_valid_aws():
    assert se._valid_aws("AKIAIOSFODNN7EXAMPLE") is False  # 문서 예제키
    assert se._valid_aws("AKIA1234567890ABCDEF") is True
    assert se._valid_aws("AAAAAAAAAAAAAAAAAAAA") is False  # 저다양성


def test_entropy_ordering():
    assert se._entropy("aaaaaaaa") < 1.5
    assert se._entropy("abcabcabc") < 3.0
    assert se._entropy("9fK2xQ7pLm4nZ8vW3bR1tY6sA0dC") > 3.5


def test_scan_text_masks_and_filters():
    # 저엔트로피 placeholder 는 제외, 유효 카드/주민번호는 마스킹되어 탐지
    rrn = _valid_rrn("900101123456")
    fs = se.scan_text(f"card 4111111111111111 rrn {rrn} pw changeme", "loc")
    cats = {f["category"] for f in fs}
    assert "sensitive-data" in cats
    for f in fs:
        assert rrn not in f["evidence"] and "4111111111111111" not in f["evidence"]  # 마스킹
