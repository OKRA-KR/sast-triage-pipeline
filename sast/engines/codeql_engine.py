"""CodeQL 엔진 어댑터 — taint/dataflow 기반. DB 생성 후 보안 쿼리 분석 → SARIF 정규화.

빌드 불필요 언어(javascript/typescript, python)만 지원. Java 등 빌드 필요 언어는
컴파일 커맨드가 있어야 하므로 이 어댑터에선 건너뛴다(빈 결과).

CodeQL CLI 위치: 환경변수 CODEQL_HOME 우선, 없으면 PATH, 없으면 ~/codeql.
"""
import json, os, shutil, subprocess, glob
from ..schema import categorize, fingerprint, new_finding

NAME = "codeql"

# 분석 스위트 (언어별)
SUITE = {"javascript": "javascript-security-extended.qls",
         "python": "python-security-extended.qls"}

def _cli():
    home = os.environ.get("CODEQL_HOME")
    if home and os.path.exists(os.path.join(home, "codeql")):
        return os.path.join(home, "codeql")
    w = shutil.which("codeql")
    if w: return w
    for p in (os.path.expanduser("~/codeql/codeql"), "/home/kali/codeql/codeql"):
        if os.path.exists(p): return p
    return None

def available():
    return _cli() is not None

def _detect_language(target):
    exts = {}
    for root, _, files in os.walk(target):
        if any(x in root for x in ("/node_modules/", "/.git/", "/dist/", "/build/")):
            continue
        for f in files:
            e = os.path.splitext(f)[1].lower()
            exts[e] = exts.get(e, 0) + 1
    if exts.get(".ts", 0) + exts.get(".js", 0) >= 5:
        return "javascript"
    if exts.get(".py", 0) >= 5:
        return "python"
    return None

def _sev_from_rule(props):
    try:
        ss = float(props.get("security-severity", ""))
        return "critical" if ss >= 9 else "high" if ss >= 7 else "medium" if ss >= 4 else "low"
    except (TypeError, ValueError):
        sev = props.get("problem.severity", "warning")
        return {"error": "high", "warning": "medium", "recommendation": "low"}.get(sev, "medium")

def run(target, out_dir):
    cli = _cli()
    lang = _detect_language(target)
    if not cli or lang not in SUITE:
        return []
    os.environ["CODEQL_ALLOW_INSTALLATION_ANYWHERE"] = "true"
    db = os.path.join(out_dir, "codeql-db")
    sarif = os.path.join(out_dir, "codeql.sarif")
    # 캐시: 이미 분석된 SARIF 가 있으면 재빌드 생략(느린 DB build/analyze 회피)
    if os.environ.get("SAST_CODEQL_CACHE") and os.path.exists(sarif):
        return parse_sarif(sarif)
    try:
        subprocess.run([cli, "database", "create", db, f"--language={lang}",
                        f"--source-root={target}", "--overwrite", "--threads=0"],
                       capture_output=True, timeout=1800)
        subprocess.run([cli, "database", "analyze", db, "--format=sarif-latest",
                        f"--output={sarif}", "--threads=0", SUITE[lang]],
                       capture_output=True, timeout=1800)
    except Exception:
        return []
    return parse_sarif(sarif)

def parse_sarif(sarif_path):
    if not os.path.exists(sarif_path):
        return []
    doc = json.load(open(sarif_path, encoding="utf-8"))
    findings = []
    for run in doc.get("runs", []):
        rules = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules[r.get("id")] = r
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            rule = rules.get(rid, {})
            props = rule.get("properties", {})
            tags = props.get("tags", [])
            cwe = [t.split("/")[-1].upper().replace("CWE-", "CWE-") for t in tags if "cwe" in t.lower()]
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            path = loc.get("artifactLocation", {}).get("uri", "")
            region = loc.get("region", {})
            s = region.get("startLine", 0); e = region.get("endLine", s)
            short = rid.split("/")[-1]
            findings.append(new_finding(
                fingerprint=fingerprint(short, path, s, ""), engines=[NAME],
                rule=short, full_rule=rid, pack="codeql",
                category=categorize(rid, cwe),
                severity=_sev_from_rule(props),
                file=path, line=s, endline=e, cwe=cwe, owasp=[],
                code="", message=(res.get("message", {}) or {}).get("text", "").strip(),
                confidence=0.5))  # taint 기반 → 기본 신뢰 부여
    return findings
