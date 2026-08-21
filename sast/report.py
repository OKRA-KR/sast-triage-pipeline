"""결과 산출 — 고정 스키마 results.json + 자체완결 대시보드 index.html."""
import json, os, datetime
from .schema import SCHEMA, group_of, SEV_ORDER

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
    for f in findings:                      # 세부 category → 분석기준 상위 그룹
        f["group"] = group_of(f["category"])
    # id 재부여(3계층 DAST 추가분 포함) — 심각도→파일 순
    for i, f in enumerate(sorted(findings, key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["file"], x["line"]))):
        f["id"] = f"F{i+1:03d}"
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
        html = tpl.replace("/*__DATA__*/null", _embed(results))
        open(os.path.join(out_dir, "index.html"), "w", encoding="utf-8").write(html)
    return results

def _embed(results):
    """JSON 을 <script> 안에 안전하게 삽입. 코드 스니펫에 들어있는 </script>·<!-- 나
    U+2028/2029(JS 문자열 깨짐)가 페이지를 부수지 않도록 이스케이프."""
    s = json.dumps(results, ensure_ascii=False)
    return (s.replace("<", "\\u003c").replace(">", "\\u003e")
             .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
