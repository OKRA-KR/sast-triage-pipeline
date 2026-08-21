"""오프라인 룰 기반 트리아지 (1.5계층) — rules/suppress.json 을 적용.
LLM 없이 오탐 억제 + 심각도 확정. 룰은 데이터 파일에서 온다."""
import json, os, re

RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "suppress.json")

def load_rules(path=RULES_PATH):
    return json.load(open(path, encoding="utf-8"))

def apply(findings, rules=None):
    rules = rules or load_rules()
    sev_by_cat = rules.get("severity_by_category", {})
    path_sup = [(re.compile(r["pattern"]), r["reason"]) for r in rules.get("path_suppress", [])]
    rule_sup = [(re.compile(r["rule"]), r["reason"]) for r in rules.get("rule_suppress", [])]
    downs = rules.get("downgrade", [])

    for f in findings:
        # 1) 카테고리 기반 기준 심각도 (엔진이 sev_lock 하면 패턴별 심각도 유지)
        if not f.get("sev_lock"):
            f["severity"] = sev_by_cat.get(f["category"], f["severity"])

        # 2) 억제 (경로/룰)
        reason = None
        for rx, why in path_sup:
            if rx.search(f["file"]): reason = why; break
        if not reason:
            for rx, why in rule_sup:
                if rx.search(f["rule"]): reason = why; break
        if reason:
            f["verdict"] = "false_positive"; f["suppressed"] = True
            f["suppress_reason"] = reason; f["severity"] = "low"
            continue

        # 3) 강등 (억제까진 아니지만 위험 낮춤)
        for d in downs:
            if d.get("category") and d["category"] != f["category"]:
                continue
            code = f.get("code", "")
            ok = True
            if "code_contains" in d: ok = d["code_contains"] in code
            elif "code_regex" in d:  ok = re.search(d["code_regex"], code) is not None
            if ok:
                f["severity"] = d.get("to_severity", f["severity"])
                f["rationale"] = (f.get("rationale") or "") + f"[강등] {d.get('reason','')}"
                break

        # 4) 오프라인 판정: 확정은 LLM/동적검증 몫 → 기본 검토필요
        f["verdict"] = "needs_review"
    return findings
