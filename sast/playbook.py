"""공격 플레이북 enrichment (1계층, 오프라인 · LLM 불필요).

rules/attack_playbook.json(ctf-web 스킬에서 증류)을 근거로, finding 의 카테고리에 맞는
탐지 프로브·PoC(공격구문)·조치를 채운다. 폐쇄망에서도 실제 공격구문/조치가 리포트에 붙는다.
3계층(LLM)이 켜지면 이 값을 근거로 더 정밀한 PoC 로 덮어쓴다(있으면).
"""
import json, os

RULES = os.path.join(os.path.dirname(__file__), "rules", "attack_playbook.json")
# 카테고리 별칭 → 플레이북 키
ALIAS = {"toctou": "missing-anti-automation"}
# 파일 확장자 → 예시코드 언어(조치 예시를 대상 언어에 맞춰 고름)
_LANG_EXT = {".java": "java", ".kt": "java", ".py": "python", ".js": "js", ".ts": "js",
             ".mjs": "js", ".jsx": "js", ".tsx": "js", ".php": "php", ".go": "go"}


def _lang_of(f):
    return _LANG_EXT.get(os.path.splitext(f.get("file") or "")[1].lower())


def _pick_example(fe, f):
    """fix_example(언어별 dict 또는 문자열) → 대상 언어 예시, 없으면 generic."""
    if isinstance(fe, str):
        return fe
    if isinstance(fe, dict):
        return fe.get(_lang_of(f) or "generic") or fe.get("generic") or next(iter(fe.values()), "")
    return ""


def load(path=RULES):
    try:
        return json.load(open(path, encoding="utf-8")).get("playbook", {})
    except (OSError, ValueError):
        return {}


def enrich(findings, pb=None):
    pb = pb if pb is not None else load()
    if not pb:
        return findings
    n = 0
    for f in findings:
        if f.get("suppressed"):
            continue
        entry = pb.get(f["category"]) or pb.get(ALIAS.get(f["category"], ""))
        if not entry:
            continue
        if not f.get("poc") and entry.get("poc"):
            poc = entry["poc"]
            if entry.get("waf_bypass"):
                poc += "\n[WAF/필터 우회] " + entry["waf_bypass"]
            f["poc"] = poc
        if not f.get("fix") and entry.get("mitigate"):
            f["fix"] = entry["mitigate"]
        if not f.get("fix_example") and entry.get("fix_example"):
            ex = _pick_example(entry["fix_example"], f)
            if ex:
                f["fix_example"] = ex               # 언어별 안전패턴 예시코드(조치방안)
        if entry.get("detect"):
            ev = f.get("evidence") or ""
            probe = "탐지 프로브: " + entry["detect"]
            if probe not in ev:
                f["evidence"] = (ev + " | " if ev else "") + probe
        f["playbook"] = entry.get("ref", "ctf-web")
        n += 1
    if n:
        print(f"[*] 플레이북 enrichment: {n}건에 공격구문/조치 부여(오프라인)")
    return findings
