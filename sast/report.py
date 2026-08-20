"""결과 산출 — 고정 스키마 results.json + 자체완결 대시보드 index.html."""
import json, os, datetime
from .schema import SCHEMA

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE = os.path.join(ROOT, "dashboard.template.html")

def summarize(findings):
    live = [f for f in findings if not f["suppressed"]]
    def cnt(p): return sum(1 for f in findings if p(f))
    return dict(
        total=len(findings),
        suppressed=cnt(lambda f: f["suppressed"]),
        true_positive=cnt(lambda f: f["verdict"] == "true_positive"),
        false_positive=cnt(lambda f: f["verdict"] == "false_positive"),
        needs_review=cnt(lambda f: f["verdict"] == "needs_review"),
        dynamic_confirmed=cnt(lambda f: (f.get("dynamic") or {}).get("status") == "confirmed"),
        by_severity={k: sum(1 for f in live if f["severity"] == k)
                     for k in ("critical", "high", "medium", "low")},
    )

def build(name, target, engines, findings, out_dir, mode="layer1"):
    os.makedirs(out_dir, exist_ok=True)
    results = dict(
        meta=dict(target=name, source=target,
                  scanned_at=datetime.date.today().isoformat(),
                  scanner=" + ".join(engines) if engines else "none",
                  mode=mode, schema=SCHEMA),
        summary=summarize(findings),
        findings=findings)
    json.dump(results, open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8"),
              indent=2, ensure_ascii=False)
    if os.path.exists(TEMPLATE):
        tpl = open(TEMPLATE, encoding="utf-8").read()
        html = tpl.replace("/*__DATA__*/null", json.dumps(results, ensure_ascii=False))
        open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8").write(html)
    return results
