"""Semgrep 엔진 어댑터 — 실행 후 통합 finding 으로 정규화."""
import json, os, shutil, subprocess
from ..schema import categorize, fingerprint, new_finding, SEMGREP_SEV

NAME = "semgrep"
CONFIGS = ["p/owasp-top-ten", "p/javascript", "p/typescript", "p/python", "p/secrets"]

def available():
    return shutil.which("semgrep") is not None

def run(target, out_dir):
    raw = os.path.join(out_dir, "semgrep.json")
    cmd = ["semgrep", "scan"]
    for c in CONFIGS:
        cmd += ["--config", c]
    cmd += ["--exclude", "node_modules", "--exclude", "dist", "--exclude", "build",
            "--json", "--output", raw, "--metrics", "off", "--quiet"]
    subprocess.run(cmd, cwd=target, timeout=1800)
    sg = json.load(open(raw, encoding="utf-8"))

    findings = []
    for r in sg.get("results", []):
        path, s, e = r["path"], r["start"]["line"], r["end"]["line"]
        ex = r.get("extra", {}); md = ex.get("metadata", {})
        rule = r["check_id"].split(".")[-1]
        cwe = md.get("cwe") or []; owasp = md.get("owasp") or []
        ctx = ""
        try:
            L = open(os.path.join(target, path), encoding="utf-8", errors="replace").read().splitlines()
            a, b = max(0, s - 4), min(len(L), e + 3)
            ctx = "\n".join(f"{n+1:>4}| {L[n]}" for n in range(a, b))
        except Exception:
            pass
        findings.append(new_finding(
            fingerprint=fingerprint(rule, path, s, ctx), engines=[NAME],
            rule=rule, category=categorize(r["check_id"], cwe),
            severity=SEMGREP_SEV.get(ex.get("severity", "INFO"), "low"),
            file=path, line=s, endline=e, cwe=cwe, owasp=owasp,
            code=ctx, message=ex.get("message", "").strip()))
    return findings
