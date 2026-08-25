"""SAST↔캡처 상관분석 (P2, IAST-lite) — 정적 발견을 실트래픽 증거로 대조.

Track A(SAST: 파일:라인, 취약 클래스)와 Track C(캡처: 실제 관측된 엔드포인트/파라미터/
라이브 증상)를 엮는다. 패킷 0 — 이미 확보한 캡처만 사용.

두 방향:
  (1) 긍정 상관[항상] — SAST 가 지목한 코드가 캡처의 실제 엔드포인트에 대응하면
      "도달 가능(데드코드 오탐 아님)" 확인 → 신뢰↑. 같은 엔드포인트에 라이브 증상
      (SQL 오류 등)이 SAST 취약 클래스와 일치하면 → true_positive 승격 + dynamic 확증.
  (2) 부정 강등[기본 OFF] — 어떤 엔드포인트에도 대응 안 되면 도달불가 후보.
      단, 캡처는 항상 부분적이라 "안 보임 = 데드코드"는 근거가 약함 → 기본 비활성.
      SAST_CORR_DEMOTE=1 일 때만 reachable="unobserved" 태그(심각도는 안 건드림).

crossval(taint 축)과 상보적: 이건 "실제 트래픽" 이라는 두 번째 증거축.
"""
import os, re
from .capture import _SQL_ERR, _STACK, _headers, _body_params

# 라우트 토큰에서 버릴 일반 단어(파일/URL 공통 관용구)
_GENERIC = {"index", "main", "app", "api", "controller", "controllers", "handler", "handlers",
            "route", "routes", "router", "service", "services", "src", "public", "www", "htdocs",
            "web", "pages", "page", "views", "view", "lib", "core", "common", "v1", "v2", "default",
            "home", "list", "action", "actions", "do", "php", "jsp", "asp", "aspx"}
# SAST 코드/메시지에서 파라미터명 추출
_PARAM_RE = re.compile(r"""\$_(?:POST|GET|REQUEST|COOKIE)\s*\[\s*['"]([\w-]+)['"]|"""
                       r"""req\.(?:query|body|params)\.(\w+)|"""
                       r"""req\.(?:query|body|params)\[\s*['"]([\w-]+)['"]|"""
                       r"""params\[:?['"]?(\w+)['"]?\]|"""
                       r"""@Request(?:Param|Body|Attribute)\s*(?:\(\s*['"]?(\w+))?|"""
                       r"""getParameter\(\s*['"](\w+)['"]""")

# SAST 취약 클래스 → 캡처 라이브 증상
_CLASS_SYMPTOM = {"sql-injection": "sql_error", "nosql-injection": "sql_error"}


def _tokens(text):
    toks = {t.lower() for t in re.split(r"[^A-Za-z0-9]+", text or "") if len(t) >= 3}
    return toks - _GENERIC


def _stem_tokens(filepath):
    """소스 파일경로 → 라우트성 토큰(basename stem + 의미있는 부모 세그먼트)."""
    base = os.path.basename(filepath or "")
    stem = re.sub(r"\.\w+$", "", base)
    parents = os.path.dirname(filepath or "").replace("\\", "/").split("/")[-2:]
    toks = _tokens(stem) | {t for p in parents for t in _tokens(p)}
    return stem.lower(), toks


def _match(stem, ftoks, ep):
    """파일 토큰이 엔드포인트(URL) 에 대응하는가? (strong=basename 세그먼트 일치)."""
    segs = ep["_segtoks"]
    if stem and len(stem) >= 4:
        for s in segs:
            if stem == s or (len(s) >= 4 and (stem in s or s in stem)):
                return "strong"
    overlap = ftoks & segs
    if overlap:
        return "weak"
    return None


def _index(exchanges):
    """캡처 → 엔드포인트별 인덱스: URL 토큰·파라미터·라이브 증상."""
    eps = {}
    for ex in exchanges:
        key = (ex["method"], ex["path"])
        e = eps.get(key)
        if not e:
            e = eps[key] = dict(method=ex["method"], path=ex["path"], url=ex["url"],
                                _segtoks=_tokens(ex["path"]), params=set(), symptoms=set())
        for k, _ in ex["query"]:
            e["params"].add(k)
        for k, _v, _l in _body_params(ex):
            e["params"].add(k)
        body = ex.get("resp_body") or ""
        if body:
            if _SQL_ERR.search(body):
                e["symptoms"].add("sql_error")
            if _STACK.search(body):
                e["symptoms"].add("stacktrace")
    return list(eps.values())


def _params_of(f):
    got = set()
    for txt in (f.get("code", ""), f.get("message", ""), f.get("evidence", "")):
        for m in _PARAM_RE.finditer(txt or ""):
            got |= {g for g in m.groups() if g}
    return got


def apply(findings, exchanges):
    """SAST 발견을 캡처 엔드포인트로 상관. findings 를 제자리 갱신하고 반환."""
    if not exchanges:
        return findings
    eps = _index(exchanges)
    if not eps:
        return findings
    demote = bool(os.environ.get("SAST_CORR_DEMOTE"))
    # SAST 소스 발견만 대상(패시브/DAST 발견 자신은 제외)
    sast = [f for f in findings if f.get("source", "SAST") == "SAST"
            and not f.get("suppressed") and f.get("file")]

    reach = promo = unobs = 0
    for f in sast:
        stem, ftoks = _stem_tokens(f["file"])
        best = None
        for ep in eps:
            q = _match(stem, ftoks, ep)
            if q and (best is None or (q == "strong" and best[0] == "weak")):
                best = (q, ep)
                if q == "strong":
                    break
        if not best:
            if demote and len(eps) >= 8:
                f["reachable"] = "unobserved"
                f["rationale"] = (f.get("rationale") or "") + \
                    "[상관] 캡처 트래픽에서 대응 엔드포인트 미관측(도달불가 후보 — 캡처 범위 한계 주의)."
                unobs += 1
            continue

        quality, ep = best
        f["reachable"] = "reachable"
        note = f"[상관] 실제 관측 엔드포인트 대응: {ep['method']} {ep['path']}"
        # 파라미터 교차: SAST 가 지목한 파라미터가 그 엔드포인트에 실재
        pmatch = _params_of(f) & ep["params"]
        if pmatch:
            note += f" · 파라미터 확인({', '.join(sorted(pmatch))})"
        # 라이브 증상 상관 → 승격
        symptom = _CLASS_SYMPTOM.get(f["category"])
        strong_hit = symptom and symptom in ep["symptoms"]
        if strong_hit or (quality == "strong" and pmatch):
            f["corroborated"] = True
            f["confidence"] = min(1.0, (f.get("confidence") or 0.0) + 0.3)
            if strong_hit:
                f["verdict"] = "true_positive"
                f["dynamic"] = {"status": "corroborated",
                                "evidence": f"동일 엔드포인트 응답에 {symptom} 관측 — 정적 {f['category']} 발견과 일치"}
                note += f" · 라이브 증상({symptom}) 일치 → 확증"
            promo += 1
        else:
            f["confidence"] = min(1.0, (f.get("confidence") or 0.0) + 0.12)
        f["rationale"] = (f.get("rationale") or "") + note + "."
        reach += 1

    if reach or unobs:
        msg = f"[*] 상관분석(SAST↔캡처): 도달확인 {reach} · 승격/확증 {promo}"
        if demote:
            msg += f" · 미관측 태그 {unobs}"
        print(msg)
    return findings
