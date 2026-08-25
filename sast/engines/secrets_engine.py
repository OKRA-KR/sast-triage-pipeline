"""평문 중요정보 스캐너 — 시크릿/자격증명/규제 개인정보 탐지 (stdlib 정규식, 오프라인).

폐쇄망 1계층 철학: 외부 툴 없이 항상 동작. 패턴은 rules/secrets_patterns.json(데이터 주도).
국내외 컴플라이언스 매핑(개인정보보호법 고유식별정보, PCI-DSS, ISMS-P, OWASP, CWE).
오탐 최소화: 카드=Luhn, 주민번호=체크섬, 제네릭 키=플레이스홀더/env 참조 제외.
안전: 탐지값은 마스킹해서 evidence/코드컨텍스트에 넣는다(평문 노출 방지).
"""
import base64, json, math, os, re
from collections import Counter
from ..schema import fingerprint, new_finding

NAME = "secrets-scan"
RULES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules", "secrets_patterns.json")

SKIP_DIRS = {".git", "node_modules", "dist", "build", "out", "vendor", "coverage",
             "target", ".gradle", ".idea", "__pycache__", ".venv", "venv"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".pdf", ".zip",
            ".gz", ".tar", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".bin", ".lock", ".map"}
SKIP_NAME = re.compile(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|"
                       r"Gemfile\.lock|poetry\.lock|Cargo\.lock|.*\.min\.(js|css))$")
MAX_BYTES = 2_000_000     # 2MB 초과 파일 스킵
MAX_LINE = 4000           # 미니파이드 등 초장문 라인 스킵


def available():
    return os.path.exists(RULES)


def _luhn(num):
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if len(d) < 12:
        return False
    s, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        s += x; alt = not alt
    return s % 10 == 0


def _rrn(num):
    """주민등록번호 체크섬(마지막 자리) 검증 + 월/일 유효성."""
    d = re.sub(r"\D", "", num)
    if len(d) != 13:
        return False
    mm, dd = int(d[2:4]), int(d[4:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    chk = (11 - (sum(int(d[i]) * w[i] for i in range(12)) % 11)) % 10
    return chk == int(d[12])


def _entropy(s):
    """Shannon 엔트로피(bits/char). 낮으면 반복/사전어 → 진짜 키 아님."""
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _valid_jwt(s):
    """구조 검증: 3개 base64url 파트 + 헤더가 alg/typ 담은 JSON 으로 디코드."""
    parts = s.split(".")
    if len(parts) != 3:
        return False
    try:
        hdr = parts[0] + "=" * (-len(parts[0]) % 4)
        obj = json.loads(base64.urlsafe_b64decode(hdr))
        return isinstance(obj, dict) and ("alg" in obj or "typ" in obj)
    except Exception:
        return False


_AWS_DUMMY = {"AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7XXXXXXX"}


def _valid_aws(s):
    """AWS 문서 예제키/저다양성 값 제외."""
    return s not in _AWS_DUMMY and len(set(s)) >= 5


def _krbiz(num):
    """사업자등록번호(10자리) 체크섬 검증 — 오탐↓."""
    d = re.sub(r"\D", "", num)
    if len(d) != 10:
        return False
    w = [1, 3, 7, 1, 3, 7, 1, 3, 5]
    s = sum(int(d[i]) * w[i] for i in range(9)) + (int(d[8]) * 5) // 10
    return (10 - (s % 10)) % 10 == int(d[9])


VALIDATORS = {"luhn": _luhn, "rrn": _rrn, "jwt": _valid_jwt, "aws_key": _valid_aws, "krbiz": _krbiz}


def _rejected(p, val, full):
    """검증 실패면 True — validator(구조) + entropy_min(무작위성) 게이트."""
    v = p.get("validator")
    if v and not VALIDATORS[v](full):
        return True
    emin = p.get("entropy_min")
    if emin and _entropy(val) < emin:
        return True
    return False


def _redact(s):
    s = s.strip()
    if len(s) <= 6:
        return (s[0] if s else "") + "***"
    return s[:4] + "…" + "*" * 4 + s[-2:]


def _load():
    doc = json.load(open(RULES, encoding="utf-8"))
    deny = [d.lower() for d in doc.get("placeholder_deny", [])]
    pats = []
    allow_disabled = bool(os.environ.get("SAST_SECRETS_ALL"))
    for p in doc.get("patterns", []):
        if not p.get("enabled", True) and not allow_disabled:
            continue
        try:
            rx = re.compile(p["regex"])
        except re.error:
            continue
        pats.append((p, rx))
    return pats, deny


def run(target, out_dir):
    if not available():
        return []
    pats, deny = _load()
    findings = []
    seen = set()
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext in SKIP_EXT or SKIP_NAME.search(fn):
                continue
            fp = os.path.join(root, fn)
            try:
                if os.path.getsize(fp) > MAX_BYTES:
                    continue
                with open(fp, encoding="utf-8", errors="strict") as fh:
                    lines = fh.read().splitlines()
            except (OSError, UnicodeDecodeError):
                continue  # 바이너리/읽기불가 스킵
            rel = os.path.relpath(fp, target).replace("\\", "/")
            for ln, line in enumerate(lines, 1):
                if len(line) > MAX_LINE:
                    continue
                for p, rx in pats:
                    for m in rx.finditer(line):
                        val = m.group(p.get("group", 0)) or m.group(0)
                        # 플레이스홀더/환경변수 참조 제외(제네릭 대입만)
                        if p.get("placeholder_check"):
                            low = val.lower()
                            if any(x in low for x in deny) or len(set(val)) < 4:
                                continue
                        if _rejected(p, val, m.group(0)):
                            continue
                        key = (p["id"], rel, ln, val)
                        if key in seen:
                            continue
                        seen.add(key)
                        masked = _redact(val)
                        ctx = _ctx(lines, ln, val)
                        comp = ", ".join(p.get("compliance", []))
                        findings.append(new_finding(
                            fingerprint=fingerprint(p["id"], rel, ln, val),
                            engines=[NAME], rule=p["id"], full_rule=p["id"], pack="secrets-scan",
                            category=p["category"], severity=p["severity"], sev_lock=True,
                            confidence=0.9, file=rel, line=ln, endline=ln,
                            cwe=p.get("cwe", []), compliance=p.get("compliance", []),
                            code=ctx, message=f"{p['name']} 평문 노출 — {masked}"
                                              + (f"  [규정: {comp}]" if comp else ""),
                            evidence=masked,
                            rationale=f"평문 저장된 중요정보({p['name']}). 규정상 암호화/제거 대상"
                                      + (f" — {comp}." if comp else ".")))
    return findings


def scan_text(text, location, source="OKRA-DAST"):
    """임의 텍스트(예: DAST 응답 본문)에서 중요정보 탐지 — run() 과 동일 룰/검증/마스킹 재사용.
    라이브로 노출된 시크릿/개인정보(주민번호·카드 등)를 잡는다."""
    pats, deny = _load()
    findings, seen = [], set()
    for ln, line in enumerate((text or "").splitlines(), 1):
        if len(line) > MAX_LINE:
            continue
        for p, rx in pats:
            for m in rx.finditer(line):
                val = m.group(p.get("group", 0)) or m.group(0)
                if p.get("placeholder_check"):
                    low = val.lower()
                    if any(x in low for x in deny) or len(set(val)) < 4:
                        continue
                if _rejected(p, val, m.group(0)):
                    continue
                key = (p["id"], location, val)
                if key in seen:
                    continue
                seen.add(key)
                masked = _redact(val)
                comp = ", ".join(p.get("compliance", []))
                findings.append(new_finding(
                    fingerprint=fingerprint("okra-" + p["id"], location, ln, val),
                    engines=[source], rule=p["id"], full_rule=p["id"], pack="okra",
                    category=p["category"], severity=p["severity"], sev_lock=True, confidence=0.9,
                    source=source, file=location, line=ln, cwe=p.get("cwe", []),
                    compliance=p.get("compliance", []),
                    message=f"{p['name']} 라이브 노출 — {masked}" + (f"  [규정: {comp}]" if comp else ""),
                    evidence=masked, verdict="true_positive",
                    dynamic={"status": "confirmed", "evidence": f"응답에서 {p['name']} 노출: {masked}"},
                    rationale=f"라이브 응답에 평문 {p['name']} 노출 — 규정상 즉시 조치 대상."))
    return findings


def _ctx(lines, ln, secret):
    """주변 코드 컨텍스트(시크릿은 마스킹). semgrep 어댑터와 동일 포맷."""
    a, b = max(0, ln - 3), min(len(lines), ln + 2)
    masked = _redact(secret)
    out = []
    for n in range(a, b):
        text = lines[n].replace(secret, masked) if secret else lines[n]
        out.append(f"{n+1:>4}| {text}")
    return "\n".join(out)
