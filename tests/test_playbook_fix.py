"""조치방안: 카테고리별 안전패턴 예시코드(fix_example) — 대상 언어에 맞춰 선택."""
from sast import playbook


def test_fix_example_language_aware():
    fs = [
        {"category": "idor", "file": "src/OrderController.java"},
        {"category": "sql-injection", "file": "app/views.py"},
        {"category": "xss", "file": "web/app.js"},
    ]
    playbook.enrich(fs)
    assert "ForbiddenException" in fs[0]["fix_example"]        # java 예시
    assert "cur.execute" in fs[1]["fix_example"]               # python 예시
    assert "textContent" in fs[2]["fix_example"]               # js 예시
    # 조치 텍스트(fix)도 함께
    assert fs[0].get("fix")


def test_fix_example_generic_fallback():
    f = [{"category": "ssrf", "file": "svc/main.go"}]            # go 예시 없음 → generic
    playbook.enrich(f)
    assert "화이트리스트" in f[0]["fix_example"]


def test_idor_has_remediation_now():
    # 이전엔 idor 엔트리가 비어 조치가 없었음 → 채워졌는지
    f = [{"category": "idor", "file": "x.py"}]
    playbook.enrich(f)
    assert f[0].get("fix") and f[0].get("fix_example")
