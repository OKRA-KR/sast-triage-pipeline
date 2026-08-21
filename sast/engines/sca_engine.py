"""SCA 엔진 — 의존성의 알려진 CVE 탐지 (OWASP A06 / 취약 컴포넌트).

osv-scanner(단일 바이너리 + 오프라인 OSV DB 지원 → 폐쇄망 적합)를 감싼다.
osv-scanner 의 재귀 walk 는 9P 마운트(/mnt/c)에서 lockfile 을 못 찾으므로,
파이썬 os.walk 로 lockfile 을 찾아 -L 로 직접 넘긴다.

CLI 위치: 환경변수 OSV_SCANNER > PATH > ~/osv-scanner > /home/kali/osv-scanner.
폐쇄망: SAST_OSV_OFFLINE=1 이면 사전 다운로드한 로컬 OSV DB 로 오프라인 스캔.
끄기: SAST_NO_SCA=1.
"""
import json, os, shutil, subprocess
from ..schema import fingerprint, new_finding
from .. import env

NAME = "sca"

# osv-scanner 가 파일명으로 인식하는 lockfile/manifest
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "requirements.txt", "poetry.lock", "Pipfile.lock", "pdm.lock",
    "go.mod", "Gemfile.lock", "composer.lock", "Cargo.lock",
    "pom.xml", "gradle.lockfile", "buildscript-gradle.lockfile",
    "packages.lock.json", "conan.lock", "mix.lock", "pubspec.lock",
}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "out", "vendor", "target",
             ".gradle", ".venv", "venv", "__pycache__"}
GHSA_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}


def _cli():
    return env.tool_path("osv-scanner", env_var="OSV_SCANNER",
                         extra_dirs=("/home/kali/osv-scanner",))


def available():
    return _cli() is not None


def _find_lockfiles(target):
    found = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f in LOCKFILES:
                found.append(os.path.join(root, f))
    return found


def _sev_from_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def _fixed_version(v):
    for a in v.get("affected", []):
        for rng in a.get("ranges", []):
            for e in rng.get("events", []):
                if e.get("fixed"):
                    return e["fixed"]
    return ""


def run(target, out_dir):
    cli = _cli()
    if not cli:
        return []
    locks = _find_lockfiles(target)
    if not locks:
        return []
    out_json = os.path.join(out_dir, "osv.json")
    cmd = [cli, "scan", "source", "--format", "json", "--output-file", out_json]
    if os.environ.get("SAST_OSV_OFFLINE"):
        cmd += ["--offline", "--experimental-offline-vulnerabilities"]  # 사전 다운로드 DB
    for lf in locks:
        cmd += ["-L", lf]
    try:
        subprocess.run(cmd, capture_output=True, timeout=1800)
    except Exception as e:
        print("[!] osv-scanner 실행 예외:", e)
        return []
    return parse(out_json, target)


def parse(out_json, target):
    if not os.path.exists(out_json):
        return []
    try:
        doc = json.load(open(out_json, encoding="utf-8"))
    except (ValueError, OSError):
        return []
    findings = []
    for r in doc.get("results", []):
        src = r.get("source", {}).get("path", "")
        rel = os.path.relpath(src, target).replace("\\", "/") if src else ""
        for p in r.get("packages", []):
            pkg = p.get("package", {})
            name, ver, eco = pkg.get("name", ""), pkg.get("version", ""), pkg.get("ecosystem", "")
            vmap = {v.get("id"): v for v in p.get("vulnerabilities", [])}
            groups = p.get("groups") or [
                {"ids": [v.get("id")], "aliases": v.get("aliases", []), "max_severity": ""}
                for v in p.get("vulnerabilities", [])]
            for g in groups:
                ids = g.get("ids", [])
                aliases = g.get("aliases", ids)
                v = next((vmap[i] for i in ids if i in vmap), {})
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                primary = cve or (ids[0] if ids else "UNKNOWN")
                sev = _sev_from_cvss(g.get("max_severity"))
                if not sev:
                    ds = (v.get("database_specific") or {}).get("severity", "")
                    sev = GHSA_SEV.get(str(ds).upper(), "medium")
                cwe = (v.get("database_specific") or {}).get("cwe_ids", []) or []
                summary = (v.get("summary") or v.get("details") or "알려진 취약점")[:200]
                fixed = _fixed_version(v)
                code = f"{name}@{ver}  ({eco})" + (f"   → 수정본 {fixed}" if fixed else "")
                findings.append(new_finding(
                    fingerprint=fingerprint(primary, rel, 0, name + ver),
                    engines=[NAME], rule=primary, full_rule=",".join(ids), pack="sca",
                    category="supply-chain", severity=sev, sev_lock=True, confidence=0.95,
                    file=rel, line=0, cwe=cwe, compliance=["OWASP-A06:2021"] + ([cve] if cve else []),
                    code=code, message=f"{name}@{ver}: {summary}",
                    evidence=", ".join(aliases[:4]),
                    fix=(f"{fixed} 이상으로 업그레이드" if fixed else "패치 버전 확인"),
                    rationale=f"알려진 취약 의존성({primary}) — 공급망(A06)."))
    return findings
