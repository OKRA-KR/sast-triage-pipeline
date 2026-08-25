"""Track B — OKRA DAST (엔진: OWASP ZAP, Apache-2.0).

OKRA DAST = OKRA 의 동적 점검. 성숙한 스캔 엔진으로 OWASP ZAP(spider + AJAX 스파이더(JS) +
active scan)을 구동하고, 그 위에 **OKRA 고유 로직**을 얹는다:
  - ZAP alert 를 통합 스키마로 정규화(유형별 집계)
  - **응답 본문에 OKRA secrets/PII 엔진 적용** → 라이브로 노출된 주민번호·카드·토큰 탐지
    (ZAP 이 못 하는 국내 컴플라이언스 중요정보)

ZAP 은 오프라인 자바 앱 → 폐쇄망 반입 가능(엔진 크레딧: OWASP ZAP).
연결: ZAP_URL(기본 127.0.0.1:8090). 없으면 tools/zap 또는 ~/ZAP 런처로 자동 기동.
인증: SAST_HTTP_COOKIE 를 replacer 로 주입. 옵션: SAST_ZAP_AJAX=1, SAST_ZAP_ASCAN_MIN(기본 20분).
"""
import json, os, secrets, time, glob, subprocess, urllib.request, urllib.parse
from .schema import categorize, fingerprint, new_finding
from .engines import secrets_engine
from . import env, capture

ZAP_URL = os.environ.get("ZAP_URL", "http://127.0.0.1:8090").rstrip("/")
# 하드코딩 키 제거 — 세션마다 랜덤(자체 기동 데몬에 주입). 외부 ZAP 연결 시 ZAP_API_KEY 로 지정.
ZAP_KEY = os.environ.get("ZAP_API_KEY") or secrets.token_hex(16)
RISK = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
_started = [None]


def _api(path, timeout=60, **params):
    params["apikey"] = ZAP_KEY
    url = ZAP_URL + path + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _alive():
    try:
        _api("/JSON/core/view/version/", timeout=10); return True
    except Exception:
        return False


def _find_launcher():
    for p in (os.path.join(env.tools_dir(), "zap", "zap.sh"),
              *glob.glob(os.path.expanduser("~/ZAP_*/zap.sh")),
              "/home/kali/ZAP_2.17.0/zap.sh"):
        if os.path.isfile(p):
            return p
    return None


def _launch():
    if _alive():
        return True
    sh = _find_launcher()
    if not sh:
        return False
    port = urllib.parse.urlparse(ZAP_URL).port or 8090
    print("[*] ZAP 데몬 기동…(최초 ~60s)")
    _started[0] = subprocess.Popen(
        [sh, "-daemon", "-host", "127.0.0.1", "-port", str(port),
         "-dir", os.path.join(env.tools_dir(), "zaphome"), "-config", "api.key=" + ZAP_KEY],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(60):
        time.sleep(3)
        if _alive():
            return True
    return False


def _poll(path, scanId, timeout, label):
    end = time.time() + timeout
    while time.time() < end:
        try:
            st = int(_api(path, scanId=scanId).get("status", "0"))
        except Exception:
            st = 0
        if st >= 100:
            return True
        time.sleep(4)
    print(f"[!] {label} 시간초과({timeout}s) — 부분 결과로 진행")
    return False


def available():
    return _alive() or _find_launcher() is not None


def _msg_to_exchange(m, base):
    """ZAP core/messages 항목 → capture 공통 Exchange (엔드포인트 인벤토리용)."""
    reqh_raw = m.get("requestHeader", "") or ""
    first = reqh_raw.split("\n", 1)[0].strip()
    parts = first.split(" ")
    method = parts[0] if parts else "GET"
    target = parts[1] if len(parts) > 1 else "/"
    rqh = capture._headers(reqh_raw)
    if target.startswith("http"):
        url = target
    else:
        host = rqh.get("host", "")
        scheme = urllib.parse.urlparse(base).scheme or "https"
        url = f"{scheme}://{host}{target}" if host else base.rstrip("/") + target
    resph_raw = m.get("responseHeader", "") or ""
    st_parts = resph_raw.split("\n", 1)[0].split(" ")
    status = st_parts[1] if len(st_parts) > 1 and st_parts[1].isdigit() else ""
    rsh = capture._headers(resph_raw)
    mime = (rsh.get("content-type", "").split(";")[0].strip())
    return capture._mk(method, url, rqh, m.get("requestBody", "") or "",
                       "", resph_raw, m.get("responseBody", "") or "", status, mime)


def _write_endpoints(messages, base, out_dir):
    """ZAP 크롤 결과에서 엔드포인트 인벤토리 CSV 생성 (Track C 와 동일 포맷)."""
    if not out_dir or not messages:
        return 0
    exs = [_msg_to_exchange(m, base) for m in messages]
    inv = capture.endpoints(exs)
    capture.write_endpoints_csv(inv, os.path.join(out_dir, "endpoints.csv"))
    print(f"[*] OKRA: 엔드포인트 {len(inv)}개 식별 → {out_dir}/endpoints.csv")
    return len(inv)


def scan(base_url, findings=None, out_dir=None):
    if not _launch():
        print("[!] OKRA DAST: ZAP 엔진 미가용 — 데몬/런처 없음"); return findings or []
    base = base_url.rstrip("/")
    print(f"[*] OKRA DAST: {base}  (엔진: OWASP ZAP)")
    ck = os.environ.get("SAST_HTTP_COOKIE")
    if ck:
        try:
            _api("/JSON/replacer/action/addRule/", description="okra-cookie", enabled="true",
                 matchType="REQ_HEADER", matchRegex="false", matchString="Cookie", replacement=ck)
            print("[*] OKRA: 세션 쿠키 주입")
        except Exception:
            pass
    alerts, messages = [], []
    try:
        _api("/JSON/core/action/accessUrl/", url=base, followRedirects="true", timeout=60)
        sid = _api("/JSON/spider/action/scan/", url=base, recurse="true", maxChildren="0")["scan"]
        _poll("/JSON/spider/view/status/", sid, 300, "spider")
        if os.environ.get("SAST_ZAP_AJAX"):
            print("[*] OKRA: AJAX 스파이더(JS 렌더링)…")
            _api("/JSON/ajaxSpider/action/scan/", url=base, inScope="false")
            end = time.time() + 300
            while time.time() < end:
                if _api("/JSON/ajaxSpider/view/status/").get("status") == "stopped":
                    break
                time.sleep(4)
        time.sleep(3)   # passive scan 소화
        aid = _api("/JSON/ascan/action/scan/", url=base, recurse="true", inScopeOnly="false")["scan"]
        _poll("/JSON/ascan/view/status/", aid, int(os.environ.get("SAST_ZAP_ASCAN_MIN", "20")) * 60, "active scan")
        alerts = _api("/JSON/core/view/alerts/", baseurl=base, start="0", count="2000").get("alerts", [])
        messages = _api("/JSON/core/view/messages/", baseurl=base, start="0", count="3000").get("messages", [])
    except Exception as e:
        print("[!] OKRA DAST(ZAP) 예외:", str(e)[:150])
    finally:
        if _started[0]:
            try:
                _api("/JSON/core/action/shutdown/")
            except Exception:
                pass
    # alert 유형별 집계 — 같은 이슈가 URL 마다 뜨는 노이즈를 1건으로(위치 수·샘플 포함)
    groups = {}
    for a in alerts:
        key = str(a.get("pluginId") or a.get("name"))
        groups.setdefault(key, []).append(a)
    uniq = [_to_finding_agg(items) for items in groups.values()]
    uniq.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f["severity"], 5))
    print(f"[*] OKRA DAST(ZAP 엔진): alert {len(alerts)} → 이슈유형 {len(uniq)}건(집계)")
    _write_endpoints(messages, base, out_dir)     # 엔드포인트 인벤토리 CSV

    # OKRA 고유: ZAP 이 크롤한 응답 본문에 secrets/PII 엔진 적용 → 라이브 중요정보 노출
    okra_sec, seen_sec = [], set()
    for m in messages:
        body = m.get("responseBody") or ""
        if not body:
            continue
        loc = (m.get("requestHeader", "").split("\n", 1)[0].split(" ")[1:2] or [""])[0] or base
        for f in secrets_engine.scan_text(body, loc, source="OKRA-DAST"):
            k = (f["rule"], f["evidence"])
            if k in seen_sec:
                continue
            seen_sec.add(k); okra_sec.append(f)
    if okra_sec:
        print(f"[*] OKRA 중요정보 스캔: 응답 {len(messages)}건 → 라이브 노출 {len(okra_sec)}건")
    return (findings or []) + uniq + okra_sec


def _to_finding_agg(items):
    """같은 alert 유형(pluginId)의 여러 인스턴스를 1 finding 으로 집계."""
    a = items[0]
    name = a.get("name", "ZAP alert")
    cwe = a.get("cweid", "")
    cwe_list = ["CWE-" + str(cwe)] if cwe and cwe not in ("-1", "0") else []
    cat = categorize(name + " " + a.get("alertRef", ""), cwe_list)
    urls = []
    for it in items:
        u = it.get("url", "")
        if u and u not in urls:
            urls.append(u)
    params = sorted({it.get("param", "") for it in items if it.get("param")})
    n = len(items)
    samples = " | ".join(urls[:5]) + (f"  (+{len(urls) - 5} more)" if len(urls) > 5 else "")
    return new_finding(
        fingerprint=fingerprint("okra-" + str(a.get("pluginId", name)), name, 0, ""),
        engines=["okra"], rule=name[:60], full_rule="okra/zap:" + str(a.get("pluginId", "")),
        pack="okra-dast", category=cat, severity=RISK.get(a.get("risk", "Low"), "low"),
        sev_lock=True, confidence=0.85, source="OKRA-DAST", verdict="true_positive",
        file=urls[0] if urls else "", line=0, cwe=cwe_list,
        message=f"[OKRA] {name} — {n}개 위치" + (f", 파라미터 {', '.join(params[:5])}" if params else ""),
        evidence=f"영향 위치 {n}개 · 샘플: {samples}",
        poc=(a.get("attack") or "")[:400],
        fix=(a.get("solution") or "")[:400],
        rationale=(a.get("description") or "")[:400])
