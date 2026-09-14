"""core.Config / ScanContext — 모드 해석·env 브리지·표시이름이 기존 행동과 일치하는지."""
import os
import types
import pytest
from sast.core import Config, ScanContext, resolve_name


def _args(**kw):
    base = dict(full=False, domain=False, active=False, cookie=None, header=[],
                insecure=False, oob=False, recon=False, no_recon=False,
                recon_passive=False, recon_wordlist=None, recon_same_port=False,
                out="out", name=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ("SAST_FULL", "SAST_ACTIVE", "SAST_1LAYER", "SAST_ONLINE", "SAST_NO_LLM",
              "SAST_NO_RECON", "SAST_HTTP_COOKIE", "SAST_HTTP_HEADERS", "SAST_INSECURE_TLS"):
        monkeypatch.delenv(k, raising=False)


def test_mode_from_flags():
    assert Config.from_args(_args(full=True)).mode == "full"
    assert Config.from_args(_args(domain=True)).mode == "domain"
    assert Config.from_args(_args(active=True)).mode == "active"
    assert Config.from_args(_args()).mode == "passive"


def test_run_active_and_recon_default():
    assert Config.from_args(_args(full=True)).run_active is True
    assert Config.from_args(_args(active=True)).run_active is True
    assert Config.from_args(_args(domain=True)).run_active is True
    assert Config.from_args(_args()).run_active is False
    assert Config.from_args(_args(active=True)).do_recon_default is True
    assert Config.from_args(_args(domain=True)).do_recon_default is False


def test_apply_mode_env_bridge_matches_legacy():
    # --full: SAST_ONLINE=1, NO_LLM 제거
    Config.from_args(_args(full=True)).apply_mode()
    assert os.environ.get("SAST_ONLINE") == "1"
    assert "SAST_NO_LLM" not in os.environ


def test_apply_mode_domain_turns_off_recon_and_llm(monkeypatch):
    Config.from_args(_args(domain=True)).apply_mode()
    assert os.environ.get("SAST_NO_LLM") == "1"
    assert os.environ.get("SAST_NO_RECON") == "1"


def test_apply_transport_cookie_header():
    Config.from_args(_args(cookie="PHPSESSID=x", header=["A: 1", "B: 2"])).apply_transport()
    assert os.environ.get("SAST_HTTP_COOKIE") == "PHPSESSID=x"
    assert os.environ.get("SAST_HTTP_HEADERS") == "A: 1;;B: 2"


def test_context_name_and_have_repo(tmp_path):
    cfg = Config.from_args(_args())
    ctx = ScanContext(config=cfg, repo=str(tmp_path))
    assert ctx.have_repo is True
    assert ctx.name == os.path.basename(str(tmp_path))
    ctx2 = ScanContext(config=cfg, verify_url="https://app.example.com/x")
    assert ctx2.name == "app.example.com"
    assert ctx2.have_repo is False


def test_resolve_name_matches_legacy():
    assert resolve_name(None, "https://h.example/x", None) == "h.example"
    assert resolve_name(None, None, "/a/b/cap2.har") == "cap2"
    assert resolve_name(None, None, None) == "scan"
    assert resolve_name("/x/y/repo", None, None, override="ovr") == "ovr"


def test_context_mark_dedups():
    ctx = ScanContext(config=Config.from_args(_args()))
    ctx.mark("a", "b", "a", "")
    assert ctx.layers == ["a", "b"]
