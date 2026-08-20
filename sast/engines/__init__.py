"""엔진 레지스트리 — 여기 등록하면 파이프라인이 자동으로 돌리고 결과를 병합한다.
CodeQL 등 새 엔진은 같은 인터페이스(available/run→findings)로 추가만 하면 됨."""
from . import semgrep_engine

ENGINES = [semgrep_engine]  # 나중에: + [codeql_engine, ...]

def run_all(target, out_dir):
    """등록된 모든 가용 엔진 실행 → fingerprint 로 dedup 병합."""
    merged = {}
    used = []
    for eng in ENGINES:
        try:
            if not eng.available():
                continue
        except Exception:
            pass
        used.append(eng.NAME)
        for f in eng.run(target, out_dir):
            fp = f["fingerprint"]
            if fp in merged:
                # 같은 지점을 다른 엔진도 잡음 → 엔진 목록 합치고 신뢰↑
                cur = merged[fp]
                cur["engines"] = sorted(set(cur["engines"]) | set(f["engines"]))
                cur["confidence"] = min(1.0, cur["confidence"] + 0.3)
            else:
                merged[fp] = f
    findings = list(merged.values())
    for i, f in enumerate(sorted(findings, key=lambda x: (x["file"], x["line"]))):
        f["id"] = f"F{i+1:03d}"
    return findings, used
