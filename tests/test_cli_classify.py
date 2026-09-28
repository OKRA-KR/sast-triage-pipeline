"""통합 진입점: 인자 자동판별(폴더/URL/캡처)."""
import os, tempfile
from sast import cli


class _A:
    def __init__(self, targets, verify=None, capture=None):
        self.targets = targets; self.verify = verify; self.capture = capture


def test_classify_url_dir_file():
    d = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile("w", suffix=".har", delete=False) as fh:
        fh.write("{}"); f = fh.name
    try:
        repo, verify, cap, spec = cli._classify(_A([d, "https://x.example", f]))
        assert repo == os.path.abspath(d)
        assert verify == "https://x.example"
        assert cap == os.path.abspath(f)          # {} 는 스펙 아님(paths/openapi 없음) → 캡처로
        assert spec is None
        assert cli._name_of(repo, verify, cap) == os.path.basename(d)
    finally:
        os.unlink(f)


def test_explicit_flags_override_and_env(monkeypatch):
    monkeypatch.delenv("SAST_VERIFY_URL", raising=False)
    monkeypatch.delenv("SAST_CAPTURE", raising=False)
    repo, verify, cap, spec = cli._classify(_A([], verify="https://v", capture="/tmp/c.xml"))
    assert (verify, cap) == ("https://v", "/tmp/c.xml")


def test_name_fallback_order():
    assert cli._name_of(None, "https://app.example.com/x", None) == "app.example.com"
    assert cli._name_of(None, None, "/a/b/capture2") == "capture2"
    assert cli._name_of(None, None, None) == "scan"
