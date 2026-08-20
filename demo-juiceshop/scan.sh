#!/usr/bin/env bash
# Layer 1 — SAST scan (reproducible). Run in WSL/Kali.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

TARGET="${1:-/home/kali/juice-shop}"
OUT="${2:-$(dirname "$0")/data}"
mkdir -p "$OUT"

echo "[*] Layer 1: Semgrep security scan on $TARGET"
semgrep scan \
  --config p/owasp-top-ten --config p/javascript --config p/typescript \
  --exclude node_modules --exclude dist --exclude build --exclude '*.min.js' \
  --json --output "$OUT/semgrep.json" --metrics off --quiet

python3 - "$TARGET" "$OUT" <<'PY'
import json, os, sys
ROOT, OUT = sys.argv[1], sys.argv[2]
d = json.load(open(os.path.join(OUT, "semgrep.json")))
out = []
for i, r in enumerate(d.get("results", [])):
    s, e = r["start"]["line"], r["end"]["line"]; ex = r.get("extra", {}); md = ex.get("metadata", {})
    ctx = ""
    try:
        L = open(os.path.join(ROOT, r["path"]), encoding="utf-8", errors="replace").read().splitlines()
        a, b = max(0, s-5), min(len(L), e+4)
        ctx = "\n".join(f"{n+1:>4}| {L[n]}" for n in range(a, b))
    except Exception as x: ctx = f"(context unavailable: {x})"
    out.append(dict(id=f"F{i+1:03d}", rule=r["check_id"].split(".")[-1], full_rule=r["check_id"],
                    path=r["path"], line=s, endline=e, severity=ex.get("severity", "INFO"),
                    cwe=md.get("cwe"), owasp=md.get("owasp"), message=ex.get("message", "").strip(), code=ctx))
json.dump(out, open(os.path.join(OUT, "findings_normalized.json"), "w"), indent=2, ensure_ascii=False)
print(f"[*] normalized {len(out)} findings -> {OUT}/findings_normalized.json")
PY

echo "[*] Next: python3 build.py  (Layer 2 triage + dashboard)"
