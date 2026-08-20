"""통합 finding 스키마 + 공통 헬퍼 (stdlib 전용)."""
import hashlib, re

SCHEMA = "sast-results/2"
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
               "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}

# 위험 카테고리 — high면 critical로 상향
DANGEROUS = {"sql-injection", "code-injection", "command-injection", "path-traversal",
             "hardcoded-secret", "deserialization", "ssti", "xxe"}

def categorize(rule_id, cwe):
    r = (rule_id or "").lower()
    c = " ".join(cwe or []).lower()
    table = [
        (("nosql", "node_nosqli"), "nosql-injection"),
        (("sql", "cwe-89"), "sql-injection"),
        (("eval", "code-string-concat", "cwe-95"), "code-injection"),
        (("command", "shell", "cwe-78"), "command-injection"),
        (("traversal", "sendfile", "cwe-73", "cwe-22"), "path-traversal"),
        (("insecure_random", "random_generator", "cwe-330", "cwe-338"), "insecure-randomness"),
        (("md5", "sha1", "weak", "node_password", "cwe-327", "cwe-328", "cwe-916"), "weak-crypto"),
        (("timing", "cwe-208"), "timing-attack"),
        (("secret", "hardcode", "jwt", "cwe-798"), "hardcoded-secret"),
        (("deserial", "cwe-502"), "deserialization"),
        (("xxe", "cwe-611"), "xxe"),
        (("redirect", "cwe-601"), "open-redirect"),
        (("directory-listing", "cwe-548"), "info-disclosure"),
        (("xss", "cwe-79"), "xss"),
        (("terraform", "aws", "subnet", "tls", "s3"), "iac-misconfig"),
        (("github-actions", "gha", "mutable"), "ci-hardening"),
        (("npm", "release-age", "dependency"), "supply-chain"),
    ]
    for keys, cat in table:
        if any(k in r or k in c for k in keys):
            return cat
    return "other"

def fingerprint(rule, file, line, code):
    """엔진 간 dedup + baseline diff 용 안정 지문."""
    norm = re.sub(r"\s+", "", code or "")[:200]
    h = hashlib.sha1(f"{rule}|{file}|{norm}".encode()).hexdigest()[:12]
    return h

def new_finding(**kw):
    base = dict(
        id="", fingerprint="", engines=[], rule="", full_rule="", pack="", category="other",
        severity="low", verdict="needs_review", confidence=0.0,
        file="", line=0, endline=0, cwe=[], owasp=[], code="", message="",
        rationale="", evidence="", fix="", poc="", reachable="unknown",
        source="SAST", dynamic=None, suppressed=False, suppress_reason="",
    )
    base.update(kw)
    return base
