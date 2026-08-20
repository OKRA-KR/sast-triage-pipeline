# SAST Draft — 2-Layer Pipeline (Juice Shop)

A working draft of the two-layer SAST design:

```
 Layer 1  ─ open-source rule engine (Semgrep)           → raw findings (SARIF/JSON)
    │        normalize + extract source→sink code context
    ▼
 Layer 2  ─ LLM triage, schema-constrained              → TP / FP / NEEDS_REVIEW
    │        verdict + exploitability + reachability + priority + evidence
    ▼
 Output   ─ self-contained HTML dashboard
```

## Target

[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) — an intentionally vulnerable
Node/TypeScript app. Cloned into WSL and scanned statically (SAST needs source, not a running app).

## Result (this run)

| metric | value |
|---|---|
| raw findings (Layer 1) | 43 |
| true positive | 22 |
| needs review | 15 |
| false positive | 6 |
| **P1 critical** | **5** — login SQLi, search SQLi, `eval()` injection, path traversal, in-repo JWT signing key |
| signal ratio | 0.51 |

The triage layer is what turns 43 raw matches into 5 things to fix first — and clears
noise a rule engine cannot judge: `_correct.tf` reference files, "public" subnets that are
public by design, path traversals neutralized by a `!file.includes('/')` guard, no-op
sanitizers, and SQLi patterns that live in training snippets rather than mounted routes.

## Files

| path | role |
|---|---|
| `scan.sh` | Layer 1 — run Semgrep, normalize, extract code context |
| `triage/verdict_schema.json` | Layer 2 — structured-output contract for the triage verdict |
| `triage/triage_prompt.md` | Layer 2 — triage system/user prompt template |
| `build.py` | Layer 2 — apply triage verdicts, emit triaged JSON + render dashboard |
| `dashboard_template.html` | dashboard template (data injected at build) |
| `dashboard.html` | **open this** — the built, self-contained dashboard |
| `data/semgrep.json` | raw Semgrep output |
| `data/findings_normalized.json` | normalized Layer-1 findings + code context |
| `data/findings_triaged.json` | Layer-1 + Layer-2 verdicts (dashboard data source) |

## Reproduce

```bash
# in WSL/Kali
export PATH="$HOME/.local/bin:$PATH"
git clone --depth 1 https://github.com/juice-shop/juice-shop.git ~/juice-shop
pipx install semgrep
./scan.sh ~/juice-shop ./data     # Layer 1
python3 build.py                  # Layer 2 + dashboard
# open dashboard.html
```

## Draft vs production

In production, **Layer 2 verdicts are produced by an LLM** constrained to
`triage/verdict_schema.json` (function-calling / JSON mode), one call per finding. In this
draft the verdicts were authored by the triage layer directly against the real scan output,
so the dashboard renders real, reviewed data end-to-end.

### Advancement hooks (next)
- **RAG context enrichment** — feed callers / route table / validators into the triage prompt.
- **Multi-judge vote** — N lenses (exploitability / mitigation / reachability), majority vote.
- **Agentic verification** — tools to grep, read callers, and run a PoC in a sandbox;
  a dynamically reproduced finding is promoted to confidence 1.0 (bridge to DAST).
- **Eval harness** — measure triage precision/recall against a labeled set.
- **Feedback loop** — confirmed verdicts → rule suppression + FN-hunting + fine-tune dataset.
