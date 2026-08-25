"""엔진 레지스트리 — 여기 등록하면 파이프라인이 자동으로 돌리고 결과를 병합한다.
CodeQL 등 새 엔진은 같은 인터페이스(available/run→findings)로 추가만 하면 됨."""
import os
from ..schema import SEV_ORDER
from . import semgrep_engine, secrets_engine, sca_engine

ROOTCAUSE_WINDOW = int(os.environ.get("SAST_DEDUP_WINDOW", "5"))

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
                # 완전 동일 지점 → 엔진 목록만 합침(신뢰가산은 아래 근본원인 클러스터에서)
                merged[fp]["engines"] = sorted(set(merged[fp]["engines"]) | set(f["engines"]))
            else:
                merged[fp] = f
    findings = _rootcause_dedup(list(merged.values()), ROOTCAUSE_WINDOW)
    for i, f in enumerate(sorted(findings, key=lambda x: (x["file"], x["line"]))):
        f["id"] = f"F{i+1:03d}"
    return findings, used


def _rootcause_dedup(findings, window=5):
    """2차(근본원인) 병합 — 같은 (file, category, 근접 라인)을 다른 룰/엔진이 각각 잡은 것을
    대표 1건 + 기여룰/엔진 목록으로 접는다. 서로 다른 엔진이 합의하면 신뢰↑(라인정확일치 대신
    클러스터 기준). category 단위라 서로 다른 취약클래스는 병합하지 않는다(재현율 보존)."""
    clusters = []
    for f in sorted(findings, key=lambda x: (x["file"], x["category"], x["line"])):
        for c in clusters:
            r = c[0]
            if (r["file"] == f["file"] and r["category"] == f["category"]
                    and abs((r["line"] or 0) - (f["line"] or 0)) <= window):
                c.append(f); break
        else:
            clusters.append([f])
    out = []
    for c in clusters:
        if len(c) == 1:
            out.append(c[0]); continue
        rep = min(c, key=lambda f: (SEV_ORDER.get(f["severity"], 9), -len(f.get("engines") or []), f["line"]))
        engines = sorted({e for f in c for e in (f.get("engines") or [])})
        rules = sorted({f.get("full_rule") or f.get("rule") for f in c if (f.get("full_rule") or f.get("rule"))})
        rep["engines"] = engines
        rep["cluster_rules"] = rules
        rep["cluster_size"] = len(c)
        if len(engines) >= 2:      # 서로 다른 엔진 합의 → 신뢰↑
            rep["confidence"] = min(1.0, (rep.get("confidence") or 0.0) + 0.3)
            rep["corroborated"] = True
        rep["rationale"] = (rep.get("rationale") or "") + \
            f"[병합] 동일 취약({rep['category']}) {len(c)}건: {', '.join(rules[:4])}."
        out.append(rep)
    return out
