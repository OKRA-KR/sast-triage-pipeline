"""CodeQL 엔진 어댑터 — taint/dataflow 기반. DB 생성 후 보안 쿼리 분석 → SARIF 정규화.

javascript/typescript · python 은 소스 추출(빌드 불필요).
Java 는 CodeQL 의 `--build-mode=none`(소스 전용 추출)으로 Maven/Gradle 빌드 없이 분석한다
— 폐쇄망/무빌드 목표에 맞춤. (빌드가 되면 정확도는 더 오르지만, 여기선 무빌드를 우선.)

CodeQL CLI 위치: 환경변수 CODEQL_HOME 우선, 없으면 PATH, 없으면 ~/codeql.
"""
import json, os, shutil, subprocess, glob, tempfile
from ..schema import categorize, fingerprint, new_finding

NAME = "codeql"

# 분석 스위트 (언어별)
SUITE = {"javascript": "javascript-security-extended.qls",
         "python": "python-security-extended.qls",
         "java": "java-security-extended.qls"}

# 명시적 build-mode 가 필요한(컴파일 언어) 언어 → none = 소스 전용 추출(무빌드)
BUILD_MODE = {"java": "none"}

# 언어 판정용 확장자
LANG_EXT = {"javascript": (".ts", ".js"), "python": (".py",), "java": (".java",)}

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
    """지원 언어 중 소스 파일이 가장 많은 언어 선택(최소 5개 이상)."""
    exts = {}
    for root, _, files in os.walk(target):
        if any(x in root for x in ("/node_modules/", "/.git/", "/dist/", "/build/", "/target/")):
            continue
        for f in files:
            e = os.path.splitext(f)[1].lower()
            exts[e] = exts.get(e, 0) + 1
    counts = {lang: sum(exts.get(x, 0) for x in ex) for lang, ex in LANG_EXT.items()}
    lang, n = max(counts.items(), key=lambda kv: kv[1])
    return lang if n >= 5 else None

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
    sarif = os.path.join(out_dir, "codeql.sarif")
    # 캐시: 이미 분석된 SARIF 가 있으면 재빌드 생략(느린 DB build/analyze 회피)
    if os.environ.get("SAST_CODEQL_CACHE") and os.path.exists(sarif):
        return parse_sarif(sarif, target)
    # DB 는 버리는 산출물 → 네이티브 임시 fs 에 생성(9P/네트워크 마운트에서 TRAP 쓰기가 느린 문제 회피).
    # SARIF 만 out_dir 에 남긴다. CODEQL_DB_DIR 로 위치 지정 가능.
    tmpbase = os.environ.get("CODEQL_DB_DIR") or tempfile.gettempdir()
    db = tempfile.mkdtemp(prefix="codeql-db-", dir=tmpbase)
    # analyze 는 쿼리별 힙이 크므로 단일 스레드+넉넉한 램(메트릭 쿼리 OOM 회피)
    ram = os.environ.get("CODEQL_RAM", "6000")
    create = [cli, "database", "create", db, f"--language={lang}",
              f"--source-root={target}", "--overwrite", "--threads=0"]
    if lang in BUILD_MODE:
        create.append(f"--build-mode={BUILD_MODE[lang]}")
    try:
        r = subprocess.run(create, capture_output=True, timeout=3600, text=True)
        if not os.path.exists(os.path.join(db, "codeql-database.yml")):
            print("[!] CodeQL DB 생성 실패:", (r.stderr or "")[-400:])
            return []
        subprocess.run([cli, "database", "analyze", db, "--format=sarif-latest",
                        f"--output={sarif}", "--threads=1", f"--ram={ram}",
                        "--sarif-add-snippets", SUITE[lang]],
                       capture_output=True, timeout=3600)
    except Exception as e:
        print("[!] CodeQL 실행 예외:", e)
        return []
    finally:
        shutil.rmtree(db, ignore_errors=True)
    return parse_sarif(sarif, target)

def _read_ctx(source_root, path, s, e):
    """소스 파일에서 finding 주변 코드 몇 줄을 읽어 컨텍스트로. (semgrep 어댑터와 동일 포맷)"""
    if not source_root or not path or not s:
        return ""
    try:
        L = open(os.path.join(source_root, path), encoding="utf-8", errors="replace").read().splitlines()
        a, b = max(0, s - 4), min(len(L), (e or s) + 3)
        return "\n".join(f"{n+1:>4}| {L[n]}" for n in range(a, b))
    except Exception:
        return ""

def parse_sarif(sarif_path, source_root=None):
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
            # 코드 컨텍스트: 소스에서 읽기 우선 → 없으면 SARIF 스니펫 → 그래도 없으면 빈값
            ctx = _read_ctx(source_root, path, s, e)
            if not ctx:
                ctx = (region.get("snippet", {}) or {}).get("text", "").rstrip()
            findings.append(new_finding(
                fingerprint=fingerprint(short, path, s, ""), engines=[NAME],
                rule=short, full_rule=rid, pack="codeql",
                category=categorize(rid, cwe),
                severity=_sev_from_rule(props),
                file=path, line=s, endline=e, cwe=cwe, owasp=[],
                code=ctx, message=(res.get("message", {}) or {}).get("text", "").strip(),
                confidence=0.5))  # taint 기반 → 기본 신뢰 부여
    return findings
