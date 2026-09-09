"""결과 산출 — 고정 스키마 results.json + 자체완결 대시보드 index.html + <name>_result.xlsx."""
import json, os, re, datetime
from urllib.parse import urlsplit
from .schema import SCHEMA, group_of, SEV_ORDER
from . import xlsx

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

def _ep_alive(e):
    """관측된 상태코드가 전부 404/무응답이면 '완전 불가' → 인벤토리서 제외. 그 외(302/401/403 포함) 유지."""
    st = {str(s) for s in e.get("statuses", set()) if str(s)}
    return not (st and st <= {"404", "0"})


# ── B: 민감 엔드포인트 분류 — 경로 패턴으로 노출 위험을 등급화(정찰→검증의 우선순위) ──
_SENSITIVE = [
    (re.compile(r"/\.git(/|$)", re.I), "critical", "소스 저장소(.git) 노출"),
    (re.compile(r"/\.(env|aws/credentials|npmrc|htpasswd)(\.|$|/)", re.I), "critical", "설정/시크릿 파일"),
    (re.compile(r"\.(bak|old|orig|swp|zip|tar|tar\.gz|tgz|sql|dump|log)$", re.I), "high", "백업/덤프 파일"),
    (re.compile(r"/actuator(/|$)|/actuator/(env|beans|heapdump|threaddump)", re.I), "high", "Spring Actuator 노출"),
    (re.compile(r"\.js\.map$|/sourcemaps?/", re.I), "high", "JS 소스맵(원본 복원)"),
    (re.compile(r"/(swagger|openapi|api-docs|redoc)(\b|/|\.json)", re.I), "medium", "API 문서/스키마"),
    (re.compile(r"/(admin|administrator|manage|management|console|dashboard)(/|$)", re.I), "medium", "관리자 경로"),
    (re.compile(r"/(internal|private|debug|test|phpinfo|server-status|metrics)(/|$|\.php)", re.I), "medium", "내부/디버그 경로"),
    (re.compile(r"/graphql(\b|/)", re.I), "low", "GraphQL(introspection 점검)"),
    (re.compile(r"/(upload|uploads|download|files?|backup)(/|$)", re.I), "low", "파일 입출력 경로"),
]


def classify_sensitivity(e):
    """엔드포인트(경로/샘플URL)를 워치리스트와 대조해 (심각도, 라벨) 반환. 해당 없으면 ('','')."""
    hay = (e.get("path") or "") + " " + (e.get("sample") or "")
    for rx, sev, label in _SENSITIVE:
        if rx.search(hay):
            return sev, label
    return "", ""


def _host_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def write_result_workbook(name, out_dir, endpoints, recon_live=None, recon_subs=None, exposure=None):
    """<name>_result.xlsx — 3시트(Endpoints·Recon·Exposure). 파일명에 대상 도메인을 박아 혼동 방지.
    Endpoints: 경로/상태코드/민감도/인증/파라미터 (404 완전불가 제외).
    Recon: 하위도메인/IP/HTTP 메타.  Exposure: 로드 본문서 흘러나온 취약정보(시크릿·오류·소스맵)."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name) or "scan"
    eh = ["Host", "Method", "Path", "Status", "Sensitivity", "Auth", "Params", "Param_Locations",
          "Content-Type", "State-Changing", "Hits", "Sample URL"]
    erows = []
    for e in sorted(endpoints, key=lambda x: (x.get("host", ""), x.get("path", ""), x.get("method", ""))):
        if not _ep_alive(e):
            continue
        locs = sorted({l for s in e.get("params", {}).values() for l in s})
        _sev, _label = classify_sensitivity(e)
        erows.append([e.get("host", ""), e.get("method", ""), e.get("path", ""),
                      "; ".join(sorted({str(s) for s in e.get("statuses", set()) if str(s)})),
                      (f"{_sev}: {_label}" if _label else ""),
                      "Y" if e.get("auth") else "N",
                      "; ".join(sorted(e.get("params", {}))), "; ".join(locs),
                      "; ".join(sorted(e.get("content_types", set()))),
                      "Y" if e.get("state_changing") else "N",
                      e.get("count", 0), e.get("sample", "")])
    rh = ["Host", "IPs", "Scheme", "Status", "Title", "Server", "Base URL"]
    live_by = {h.get("host", ""): h for h in (recon_live or [])}
    subs = recon_subs or {}
    rrows = []
    for host in sorted(set(subs) | set(live_by)):
        lv = live_by.get(host, {})
        rrows.append([host, ", ".join(subs.get(host, [])), lv.get("scheme", ""),
                      lv.get("status", ""), lv.get("title", ""), lv.get("server", ""), lv.get("base", "")])
    xh = ["Severity", "Category", "Host", "Where (URL)", "Evidence", "Fix", "Compliance"]
    xrows = []
    _sev_ord = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(exposure or [], key=lambda f: _sev_ord.get(f.get("severity"), 9)):
        ev = (f.get("evidence") or f.get("message") or "").split(" | ")[0][:200]   # 마스킹값만(덧붙은 가이드 제외)
        xrows.append([f.get("severity", ""), f.get("category", ""), _host_of(f.get("file", "")),
                      f.get("file", ""), ev, (f.get("fix") or "")[:200],
                      "; ".join(f.get("compliance", []) or [])])
    path = os.path.join(out_dir, f"{safe}_result.xlsx")
    try:
        xlsx.write(path, [("Endpoints", eh, erows), ("Recon", rh, rrows), ("Exposure", xh, xrows)])
    except OSError as e:
        print(f"[!] 결과 워크북 기록 실패: {e} — 파일을 연 프로그램(엑셀)을 닫고 재시도. (results.json 은 정상)")
        return None
    return dict(path=path, endpoints=len(erows), recon=len(rrows), exposure=len(xrows))


def build(name, target, engines, findings, out_dir, mode="layer1", truncated=False):
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
                  mode=mode, schema=SCHEMA, truncated=bool(truncated)),
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
