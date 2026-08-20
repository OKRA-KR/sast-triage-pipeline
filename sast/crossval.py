"""엔진 교차검증 (1.7계층) — 패턴 엔진의 오탐을 taint 엔진 결과로 정정.

njsscan(=semgrep p/nodejsscan)의 node_nosqli 는 흐름 분석 없이 패턴만 보므로,
Sequelize 의 파라미터라이즈드 `where` 객체까지 NoSQL 인젝션으로 오탐한다.
CodeQL taint 가 같은 파일에서 injection-계열 흐름을 확증하지 못하면 → 오탐 추정으로 강등.
반대로 확증하면 → 2엔진 합의로 신뢰를 올린다.

핵심: taint 엔진 결과가 하나도 없으면(비-deep 모드) 교차검증을 **비활성**한다.
확증 정보가 없는 상태에서 강등하면 진짜 취약점을 놓칠 수 있기 때문. (recall 보존)
룰은 rules/suppress.json 의 `crossval` 블록에서 온다(데이터 주도).
"""
import os


def _basename(p):
    return os.path.basename(p or "")


def apply(findings, rules):
    cfg = (rules or {}).get("crossval")
    if not cfg:
        return findings
    taint_engines = set(cfg.get("taint_engines", []))
    reqs = cfg.get("require_corroboration", [])
    if not taint_engines or not reqs:
        return findings

    # taint 엔진이 이번 스캔에 실제로 참여했는가? 아니면 교차검증 비활성.
    taint_present = any(taint_engines & set(f.get("engines", [])) for f in findings)
    if not taint_present:
        return findings

    # 파일별 taint 카테고리 인덱스 (exact 경로 + basename 둘 다)
    taint_cats_by_file = {}
    taint_cats_by_base = {}
    for f in findings:
        if taint_engines & set(f.get("engines", [])):
            taint_cats_by_file.setdefault(f["file"], set()).add(f["category"])
            taint_cats_by_base.setdefault(_basename(f["file"]), set()).add(f["category"])

    req_by_cat = {r["category"]: r for r in reqs}

    downgraded = corroborated = 0
    for f in findings:
        if f.get("suppressed"):
            continue
        r = req_by_cat.get(f["category"])
        if not r:
            continue
        # taint 엔진 자신이 잡은 finding 은 이미 확증 → 건너뜀
        if taint_engines & set(f.get("engines", [])):
            continue

        want = set(r.get("by_categories", []))
        here = taint_cats_by_file.get(f["file"]) or taint_cats_by_base.get(_basename(f["file"])) or set()
        if want & here:
            # 같은 파일에서 taint 가 injection 흐름을 확증 → 2엔진 합의
            f["corroborated"] = True
            f["confidence"] = min(1.0, (f.get("confidence") or 0.0) + 0.3)
            f["rationale"] = (f.get("rationale") or "") + "[교차확증] CodeQL taint 가 같은 파일에서 injection 흐름 확인."
            corroborated += 1
        else:
            # taint 미확증 → 오탐 추정으로 강등(억제는 아님 — 여전히 목록에 보임)
            f["corroborated"] = False
            f["severity"] = r.get("to_severity", f["severity"])
            f["verdict"] = r.get("verdict", f["verdict"])
            f["rationale"] = (f.get("rationale") or "") + "[교차검증] " + r.get("reason", "")
            downgraded += 1

    if downgraded or corroborated:
        print(f"[*] 교차검증(CodeQL taint): 확증 {corroborated} · 오탐추정 강등 {downgraded}")
    return findings
