"""_run_active: --active=세션없어도 접근되는대로 테스트 / --full=세션없으면 종료(None)."""
from sast import cli, login, replay
from sast.schema import new_finding


def _stub_replay(monkeypatch):
    monkeypatch.setattr(replay, "scan_capture",
                        lambda exs, a=None, b=None, oob=None: [new_finding(category="xss", file="u")])


def test_active_runs_without_session(monkeypatch):
    _stub_replay(monkeypatch)
    monkeypatch.delenv("SAST_LOGIN_USER", raising=False)
    monkeypatch.delenv("SAST_BRUTE_USER", raising=False)
    monkeypatch.setattr(login, "build_sessions", lambda exs: (None, None))   # 세션 없음
    res = cli._run_active([], [], require_session=False)
    assert res is not None and len(res) == 1        # 비인증이어도 테스트 진행


def test_full_terminates_without_session(monkeypatch):
    _stub_replay(monkeypatch)
    monkeypatch.setattr(login, "working_session", lambda exs: (False, None, None))
    res = cli._run_active([], [], require_session=True)
    assert res is None                              # 세션 못 찾으면 종료 신호


def test_full_runs_with_session(monkeypatch):
    _stub_replay(monkeypatch)
    monkeypatch.setattr(login, "working_session", lambda exs: (True, "SESS", None))
    monkeypatch.delenv("SAST_BRUTE_USER", raising=False)
    res = cli._run_active([], [], require_session=True)
    assert res is not None and len(res) == 1
