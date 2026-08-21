"""2계층 — LLM 트리아지 (개방망 전용, 외부통신).

1계층 결과(오프라인 룰+트리아지)를 LLM 이 오탐/정탐 판별하고 근거를 붙인다.
`env.layer2_enabled()`(online + LLM 설정) 일 때만 cli 가 호출한다. 미설정이면 아예 안 돎.
결과: finding 의 verdict/confidence/rationale 를 갱신(dynamic 확증된 건은 건드리지 않음).
"""
import json, os
from . import llm
from .schema import SEV_ORDER

SYSTEM = (
    "당신은 애플리케이션 보안 진단 트리아지 전문가다. 정적분석(SAST) finding 목록을 받아 "
    "각 항목이 실제 취약점(true_positive)인지 오탐(false_positive)인지, 확신이 낮으면 needs_review 인지 "
    "판별한다. 코드 컨텍스트와 룰 의미를 근거로 판단하고, 과잉 확신을 피한다. "
    "반드시 JSON 배열만 출력한다: "
    '[{"id":"F001","verdict":"true_positive|false_positive|needs_review","confidence":0.0~1.0,"rationale":"한 줄 근거"}]'
)

BATCH = 5


def _payload(f):
    return {
        "id": f["id"], "category": f["category"], "severity": f["severity"],
        "rule": f["rule"], "file": f"{f['file']}:{f['line']}",
        "message": (f.get("message") or "")[:300],
        "code": (f.get("code") or "")[:600],
    }


def triage(findings):
    if not llm.available():
        return findings
    # 대상: 억제 안 됨 + 아직 동적확증 안 됨 + 검토필요/미판정
    targets = [f for f in findings if not f.get("suppressed")
               and (f.get("dynamic") or {}).get("status") != "confirmed"
               and f.get("verdict") in ("needs_review", "untriaged", None)]
    targets.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))   # 심각도순(결정적)
    lim = os.environ.get("SAST_TRIAGE_LIMIT")                      # 테스트용 상한
    if lim:
        targets = targets[:int(lim)]
    if not targets:
        return findings
    by_id = {f["id"]: f for f in findings}
    done = tp = fp = 0
    for i in range(0, len(targets), BATCH):
        chunk = targets[i:i + BATCH]
        user = "다음 finding 들을 판별하라:\n" + json.dumps(
            [_payload(f) for f in chunk], ensure_ascii=False, indent=1)
        res = llm.complete_json(SYSTEM, user, max_tokens=3000)
        if not res:
            continue
        for r in res:
            f = by_id.get(r.get("id"))
            if not f:
                continue
            v = r.get("verdict")
            if v in ("true_positive", "false_positive", "needs_review"):
                f["verdict"] = v
                f["confidence"] = float(r.get("confidence", f.get("confidence") or 0.5))
                f["rationale"] = (f.get("rationale") or "") + "[LLM] " + str(r.get("rationale", ""))[:200]
                f["source"] = f.get("source", "SAST") + "+LLM"
                done += 1
                tp += v == "true_positive"; fp += v == "false_positive"
    print(f"[*] 2계층(LLM 트리아지): {done}건 판별 · 정탐 {tp} · 오탐 {fp}")
    return findings
