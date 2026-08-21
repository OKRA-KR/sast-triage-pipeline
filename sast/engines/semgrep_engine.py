"""Semgrep 엔진 어댑터 — 실행 후 통합 finding 으로 정규화.

폐쇄망 우선: 룰을 로컬 번들에서 로드한다(레지스트리 온라인 의존 제거).
  1) SAST_SEMGREP_RULES 환경변수(번들 경로)
  2) <repo>/sast/semgrep-rules  (툴과 함께 반입되는 기본 번들)
  3) 둘 다 없으면 semgrep 레지스트리 팩(p/…, 온라인) 으로 폴백
번들은 provision.sh 로 온라인 머신에서 미리 받는다(semgrep-rules + njsscan).
오탐 억제를 위해 번들에서 'security'/'secrets' 하위폴더만 골라 로드한다.
"""
import json, os, shutil, subprocess
from ..schema import categorize, fingerprint, new_finding, SEMGREP_SEV

NAME = "semgrep"
SAST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 온라인 폴백용 레지스트리 팩
REGISTRY_PACKS = ["p/owasp-top-ten", "p/javascript", "p/typescript", "p/python",
                  "p/java", "p/secrets", "p/security-audit", "p/nodejsscan",
                  "p/xss", "p/jwt", "p/command-injection", "p/sql-injection"]

def _bundle_dir():
    b = os.environ.get("SAST_SEMGREP_RULES")
    if b and os.path.isdir(b):
        return b
    cand = os.path.join(SAST_DIR, "semgrep-rules")   # repo-local 기본 번들
    return cand if os.path.isdir(cand) else None

# 프레임워크 룰 디렉터리는 대상에 그 언어가 있을 때만 로드(크로스언어 오탐 방지).
# generic/yaml/terraform/dockerfile/html 은 파일타입이 자체 스코핑되므로 항상 로드.
LANG_DIRS = {"java": (".java",), "javascript": (".js", ".jsx", ".mjs", ".cjs"),
             "typescript": (".ts", ".tsx"), "python": (".py",)}

def _target_langs(target):
    present = set()
    for root, _, files in os.walk(target):
        if any(x in root for x in ("/node_modules/", "/.git/", "/dist/", "/build/")):
            continue
        for f in files:
            e = os.path.splitext(f)[1].lower()
            for lang, exts in LANG_DIRS.items():
                if e in exts:
                    present.add(lang)
    return present

def _configs(target):
    """(config 리스트, offline 여부) 반환. 대상 언어에 맞는 룰만 로드."""
    b = _bundle_dir()
    if not b:
        return REGISTRY_PACKS, False
    langs = _target_langs(target)
    subs = []
    for root, dirs, _ in os.walk(b):
        rp = root.replace("\\", "/") + "/"
        if any(fr in rp for fr in NOISY_FRAGMENTS):
            dirs[:] = []; continue                    # 저신호 룰셋 스킵
        # 언어별 프레임워크 디렉터리: 대상에 그 언어 없으면 통째로 스킵
        skip = next((lang for lang in LANG_DIRS if f"/{lang}/" in rp and lang not in langs), None)
        if skip:
            dirs[:] = []; continue
        base = os.path.basename(root)
        if base in ("security", "secrets"):
            subs.append(root); dirs[:] = []
        elif base == "semantic_grep":                 # njsscan(Node) — js/ts 있을 때만
            if {"javascript", "typescript"} & langs:
                subs.append(root)
            dirs[:] = []
    return (subs, True) if subs else (REGISTRY_PACKS, False)

# 로컬 번들에서 제외할 저신호 룰 디렉터리(오탐 다발 — 레지스트리 팩도 큐레이션으로 뺌)
NOISY_FRAGMENTS = ("/jquery/",)
# pack 이름에서 걷어낼 경로/드라이브 노이즈 세그먼트
_PACK_DROP = {"home", "kali", "mnt", "c", "users", "user", "tmp", "opt",
              "semgrep-bundle", "semgrep-rules", "njsscan", "rules", "semantic_grep",
              "security", "secrets", "lang", "audit"}

def _pack(cid):
    parts = [p for p in cid.split(".") if p and p not in _PACK_DROP]
    return ".".join(parts[:2]) if parts else cid

def available():
    return shutil.which("semgrep") is not None

def run(target, out_dir):
    raw = os.path.join(out_dir, "semgrep.json")
    configs, offline = _configs(target)
    print(f"[*] semgrep 룰: {'로컬 번들(오프라인)' if offline else '레지스트리(온라인)'} · {len(configs)}개 소스")
    cmd = ["semgrep", "scan"]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["--exclude", "node_modules", "--exclude", "dist", "--exclude", "build",
            "--json", "--output", raw, "--metrics", "off", "--quiet"]
    subprocess.run(cmd, cwd=target, timeout=1800)
    sg = json.load(open(raw, encoding="utf-8"))

    findings = []
    for r in sg.get("results", []):
        path, s, e = r["path"], r["start"]["line"], r["end"]["line"]
        ex = r.get("extra", {}); md = ex.get("metadata", {})
        cid = r["check_id"]
        rule = cid.split(".")[-1]
        pack = _pack(cid)                       # 룰 출처(계열) — 로컬경로 노이즈 제거
        cwe = md.get("cwe") or []; owasp = md.get("owasp") or []
        if isinstance(cwe, str): cwe = [cwe]        # njsscan 은 문자열로 줌 → 글자분해 방지
        if isinstance(owasp, str): owasp = [owasp]
        ctx = ""
        try:
            L = open(os.path.join(target, path), encoding="utf-8", errors="replace").read().splitlines()
            a, b = max(0, s - 4), min(len(L), e + 3)
            ctx = "\n".join(f"{n+1:>4}| {L[n]}" for n in range(a, b))
        except Exception:
            pass
        findings.append(new_finding(
            fingerprint=fingerprint(rule, path, s, ctx), engines=[NAME],
            rule=rule, full_rule=cid, pack=pack, category=categorize(cid, cwe),
            severity=SEMGREP_SEV.get(ex.get("severity", "INFO"), "low"),
            file=path, line=s, endline=e, cwe=cwe, owasp=owasp,
            code=ctx, message=ex.get("message", "").strip()))
    return findings
