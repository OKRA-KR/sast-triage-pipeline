#!/usr/bin/env python3
"""
Repo-무관 SAST 파이프라인 (오프라인, LLM 불필요).

무엇을 하나:
  1) 대상 repo 에 Semgrep 실행 (1계층)
  2) 정규화 + 코드 컨텍스트 추출
  3) 코드화된 오탐 억제 룰 + 심각도 매핑 (1.5계층, 휴리스틱 트리아지)
  4) 고정 스키마 results.json 출력
  5) 자체완결 HTML(dashboard.template.html) 에 데이터 임베드 → index.html

사용:
  python3 pipeline.py --target <repo경로> --out <출력폴더> [--name <표시이름>]

LLM 트리아지(2계층)와 동적검증(3계층)은 이 파일에 훅만 두고 별도 단계에서 병합한다.
"""
import json, os, sys, subprocess, datetime, argparse, re

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- 오탐 억제 룰 (코드화된 FP-role) — repo 무관 ----------------------------
FP_PATH_PATTERNS = [
    (r"(^|/)(test|tests|__tests__|spec|specs)/", "테스트 코드"),
    (r"(^|/)(examples?|samples?|fixtures?|codefixes)/", "예제/픽스처(비-런타임)"),
    (r"_correct\.[a-z]+$", "참조-정답 파일"),
    (r"\.min\.(js|css)$", "빌드 산출물"),
    (r"(^|/)(vendor|node_modules|dist|build)/", "서드파티/빌드 산출물"),
    (r"(^|/)docs?/", "문서"),
]
# 위험 카테고리 (심각도 상향 대상)
CRITICAL_CATS = {"sql-injection","code-injection","command-injection","path-traversal",
                 "hardcoded-secret","deserialization","ssti","xxe"}
SEV_MAP = {"ERROR":"high","WARNING":"medium","INFO":"low","MEDIUM":"medium","LOW":"low","HIGH":"high","CRITICAL":"critical"}

def categorize(rule_id, cwe):
    r = rule_id.lower(); c = " ".join(cwe or []).lower()
    if "sql" in r or "cwe-89" in c: return "sql-injection"
    if "eval" in r or "code-string-concat" in r or "cwe-95" in c: return "code-injection"
    if "command" in r or "shell" in r or "cwe-78" in c: return "command-injection"
    if "traversal" in r or "sendfile" in r or "cwe-73" in c or "cwe-22" in c: return "path-traversal"
    if "secret" in r or "hardcode" in r or "jwt" in r or "cwe-798" in c: return "hardcoded-secret"
    if "redirect" in r or "cwe-601" in c: return "open-redirect"
    if "directory-listing" in r or "cwe-548" in c: return "info-disclosure"
    if "xss" in r or "cwe-79" in c: return "xss"
    if "terraform" in r or "aws" in r or "subnet" in r or "tls" in r: return "iac-misconfig"
    if "github-actions" in r or "gha" in r or "mutable" in r: return "ci-hardening"
    if "npm" in r or "release-age" in r: return "supply-chain"
    return "other"

def suppress_reason(path):
    for pat, why in FP_PATH_PATTERNS:
        if re.search(pat, path): return why
    return None

def run_semgrep(target, out_dir):
    raw = os.path.join(out_dir, "semgrep.json")
    cmd = ["semgrep","scan","--config","p/owasp-top-ten","--config","p/javascript",
           "--config","p/typescript","--config","p/python","--config","p/secrets",
           "--exclude","node_modules","--exclude","dist","--exclude","build",
           "--json","--output",raw,"--metrics","off","--quiet"]
    subprocess.run(cmd, cwd=target, timeout=1800)
    return json.load(open(raw, encoding="utf-8"))

def normalize_and_triage(sg, target):
    findings = []
    for i, r in enumerate(sg.get("results", [])):
        path = r["path"]; s = r["start"]["line"]; e = r["end"]["line"]
        ex = r.get("extra", {}); md = ex.get("metadata", {})
        rule = r["check_id"].split(".")[-1]
        cwe = md.get("cwe") or []; owasp = md.get("owasp") or []
        cat = categorize(r["check_id"], cwe)
        sev = SEV_MAP.get(ex.get("severity","INFO"), "low")
        # 심각도 상향: 위험 카테고리 + high → critical
        if cat in CRITICAL_CATS and sev == "high": sev = "critical"
        # 코드 컨텍스트
        ctx = ""
        try:
            L = open(os.path.join(target, path), encoding="utf-8", errors="replace").read().splitlines()
            a, b = max(0, s-4), min(len(L), e+3)
            ctx = "\n".join(f"{n+1:>4}| {L[n]}" for n in range(a, b))
        except Exception: pass
        # 오탐 억제 룰
        reason = suppress_reason(path)
        if reason:
            verdict, suppressed, srsn, sev2 = "false_positive", True, reason, "low"
        else:
            verdict, suppressed, srsn, sev2 = "needs_review", False, "", sev
        findings.append(dict(
            id=f"F{i+1:03d}", rule=rule, category=cat, severity=sev2,
            verdict=verdict, confidence=0.0, file=path, line=s, endline=e,
            cwe=cwe, owasp=owasp, code=ctx, message=ex.get("message","").strip(),
            rationale="", evidence="", fix="", poc="", reachable="unknown",
            source="SAST", dynamic=None, suppressed=suppressed, suppress_reason=srsn))
    return findings

def summarize(findings):
    live = [f for f in findings if not f["suppressed"]]
    def cnt(pred): return sum(1 for f in findings if pred(f))
    return dict(
        total=len(findings),
        suppressed=cnt(lambda f: f["suppressed"]),
        true_positive=cnt(lambda f: f["verdict"]=="true_positive"),
        false_positive=cnt(lambda f: f["verdict"]=="false_positive"),
        needs_review=cnt(lambda f: f["verdict"]=="needs_review"),
        dynamic_confirmed=cnt(lambda f: (f.get("dynamic") or {}).get("status")=="confirmed"),
        by_severity={k: sum(1 for f in live if f["severity"]==k) for k in ("critical","high","medium","low")},
    )

def build_index_html(results, out_dir):
    tpl = open(os.path.join(HERE, "dashboard.template.html"), encoding="utf-8").read()
    html = tpl.replace("/*__DATA__*/null", json.dumps(results, ensure_ascii=False))
    open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8").write(html)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="스캔 대상 repo 경로")
    ap.add_argument("--out", required=True, help="결과 출력 폴더")
    ap.add_argument("--name", default=None, help="표시 이름(기본: 폴더명)")
    ap.add_argument("--mode", default="layer1", help="layer1 | full (메타 표기용)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    name = a.name or os.path.basename(os.path.normpath(a.target))

    print(f"[*] Semgrep 스캔: {a.target}")
    sg = run_semgrep(a.target, a.out)
    findings = normalize_and_triage(sg, a.target)
    results = dict(
        meta=dict(target=name, source=a.target,
                  scanned_at=datetime.date.today().isoformat(),
                  scanner="Semgrep (owasp-top-ten+javascript+typescript+python+secrets)",
                  mode=a.mode, schema="sast-results/1"),
        summary=summarize(findings),
        findings=findings)
    json.dump(results, open(os.path.join(a.out,"results.json"),"w",encoding="utf-8"), indent=2, ensure_ascii=False)
    build_index_html(results, a.out)
    s = results["summary"]
    print(f"[*] {s['total']}건 (억제 {s['suppressed']} → 검토대상 {s['needs_review']}) "
          f"| 심각도 {s['by_severity']}")
    print(f"[*] 결과: {a.out}/results.json , 대시보드: {a.out}/index.html")

if __name__ == "__main__":
    main()
