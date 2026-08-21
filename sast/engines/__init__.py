"""엔진 레지스트리 — 여기 등록하면 파이프라인이 자동으로 돌리고 결과를 병합한다.
CodeQL 등 새 엔진은 같은 인터페이스(available/run→findings)로 추가만 하면 됨."""
import os
from . import semgrep_engine, secrets_engine, sca_engine

# 기본: semgrep(패턴) + secrets-scan(평문 중요정보) + sca(의존성 CVE, osv-scanner 있으면).
# SAST_DEEP=1 이면 CodeQL(taint, 느림) 추가.
# 끄기: SAST_NO_SECRETS=1 / SAST_NO_SCA=1.
ENGINES = [semgrep_engine]
if not os.environ.get("SAST_NO_SECRETS"):
    ENGINES.append(secrets_engine)
if not os.environ.get("SAST_NO_SCA"):
    ENGINES.append(sca_engine)   # available() 가 osv-scanner 부재 시 스킵
if os.environ.get("SAST_DEEP"):
    from . import codeql_engine
    ENGINES.append(codeql_engine)

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
