"""P1-4: 요청 상한 도달 시 경고 + report meta.truncated=true (조용한 부분스캔 방지)."""
import importlib
from sast import capture, report
from sast.schema import new_finding


def test_replay_sets_truncated_flag(monkeypatch, capsys):
    import importlib, sast.replay as replay
    replay = importlib.reload(replay)                  # 다른 테스트의 _send 스텁 오염 제거
    monkeypatch.setattr(replay, "MAX_REQ", 2)          # 상한 강제로 낮춤
    replay._req[0] = replay.MAX_REQ                     # 이미 상한 도달 상태
    replay._warned[0] = False; replay.truncated[0] = False
    r = replay._send("GET", "http://x/", {}, None)     # 상한이라 네트워크 전에 None
    assert r is None
    assert replay.truncated[0] is True                 # 부분스캔 플래그 세팅
    assert "요청 상한" in capsys.readouterr().out


def test_report_meta_truncated(tmp_path):
    f = new_finding(file="u", category="xss", severity="low")
    res = report.build("t", "src", ["passive"], [f], str(tmp_path), truncated=True)
    assert res["meta"]["truncated"] is True
    res2 = report.build("t", "src", ["passive"], [f], str(tmp_path), truncated=False)
    assert res2["meta"]["truncated"] is False
