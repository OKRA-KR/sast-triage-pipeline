"""P1-3: 근본원인 dedup — 같은 file+category+근접라인 병합, 다른 클래스는 보존."""
from sast.engines import _rootcause_dedup
from sast.schema import new_finding


def _f(file, cat, line, rule, engine, sev="high"):
    return new_finding(file=file, category=cat, line=line, rule=rule, full_rule=rule,
                       engines=[engine], severity=sev, confidence=0.5)


def test_merges_same_class_near_lines():
    fs = [
        _f("a.java", "sql-injection", 45, "tainted-sql-string", "semgrep"),
        _f("a.java", "sql-injection", 48, "formatted-sql-string", "codeql"),
        _f("a.java", "sql-injection", 50, "concat-sql", "semgrep"),
    ]
    out = _rootcause_dedup(fs, window=5)
    assert len(out) == 1
    rep = out[0]
    assert set(rep["engines"]) == {"semgrep", "codeql"}
    assert rep["cluster_size"] == 3
    assert rep["corroborated"] is True          # 2엔진 합의
    assert rep["confidence"] >= 0.5


def test_does_not_merge_different_category():
    fs = [
        _f("a.php", "sql-injection", 10, "sqli", "semgrep"),
        _f("a.php", "command-injection", 12, "cmd", "semgrep"),   # 근접이지만 다른 클래스
    ]
    out = _rootcause_dedup(fs, window=5)
    assert len(out) == 2
    assert {o["category"] for o in out} == {"sql-injection", "command-injection"}


def test_does_not_merge_far_lines():
    fs = [
        _f("a.php", "xss", 10, "x1", "semgrep"),
        _f("a.php", "xss", 40, "x2", "semgrep"),                  # window 밖
    ]
    assert len(_rootcause_dedup(fs, window=5)) == 2
