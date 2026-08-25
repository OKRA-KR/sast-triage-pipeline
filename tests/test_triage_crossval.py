"""P1-2: triage.apply (동적확증 보존) + crossval.apply (taint 없으면 no-op)."""
from sast import triage, crossval
from sast.schema import new_finding


def test_triage_preserves_dynamic_verdict():
    rules = triage.load_rules()
    dast = new_finding(source="PASSIVE", verdict="true_positive", category="security-misconfig",
                       severity="medium", sev_lock=True, dynamic={"status": "confirmed"}, file="u")
    sast = new_finding(source="SAST", verdict="true_positive", category="sql-injection",
                       severity="high", file="a.php")
    triage.apply([dast, sast], rules)
    assert dast["verdict"] == "true_positive"     # 동적확증은 보존
    assert sast["verdict"] == "needs_review"      # 정적은 검토대상으로


def test_crossval_noop_without_taint():
    rules = triage.load_rules()
    f = new_finding(source="SAST", category="nosql-injection", engines=["semgrep"],
                    severity="high", file="a.js", verdict="needs_review")
    before = dict(f)
    crossval.apply([f], rules)                    # taint 엔진(codeql) 없음 → 변화 없어야
    assert f["severity"] == before["severity"]
    assert f.get("corroborated") in (None, before.get("corroborated"))
