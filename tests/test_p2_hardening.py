"""P2: TLS 기본 검증 + 사업자번호 체크섬 + okra 키 비하드코딩."""
import ssl
from sast import env
from sast.engines import secrets_engine as se


def test_tls_verify_default(monkeypatch):
    monkeypatch.delenv("SAST_INSECURE_TLS", raising=False)
    ctx = env.ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED     # 기본 검증 on
    assert ctx.check_hostname is True


def test_tls_insecure_optin(monkeypatch):
    monkeypatch.setenv("SAST_INSECURE_TLS", "1")
    ctx = env.ssl_context()
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def _valid_biz():
    # 유효 체크섬 사업자번호 합성 생성
    import re
    base = "123456789"
    w = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    d = [int(c) for c in base]
    s = sum(d[i] * w[i] for i in range(9)) + (d[8] * 5) // 10
    chk = (10 - (s % 10)) % 10
    return base + str(chk)


def test_biz_checksum():
    good = _valid_biz()
    assert se._krbiz(good) is True
    bad = good[:-1] + str((int(good[-1]) + 1) % 10)
    assert se._krbiz(bad) is False


def test_okra_key_not_hardcoded():
    import importlib, sast.okra as okra
    okra = importlib.reload(okra)
    assert okra.ZAP_KEY != "sastzapkey"              # 하드코딩 키 제거
    assert len(okra.ZAP_KEY) >= 16
