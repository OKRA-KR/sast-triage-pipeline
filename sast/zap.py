"""Track B — OWASP ZAP DAST 엔진 어댑터.

성숙한 DAST(스파이더 + AJAX 스파이더(JS 실행) + active scan)를 ZAP 데몬으로 구동하고,
ZAP alert 를 통합 스키마로 정규화한다. ZAP 은 오프라인 자바 앱 → 폐쇄망 반입 가능.

연결: ZAP_URL(기본 127.0.0.1:8090) 에 연결. 없으면 tools/zap 또는 ~/ZAP 런처로 자동 기동.
인증: SAST_HTTP_COOKIE 를 replacer 규칙으로 모든 요청에 주입.
옵션: SAST_ZAP_AJAX=1(JS 스파이더), SAST_ZAP_ASCAN_MIN(active scan 상한 분, 기본 20).
"""
import json, os, time, glob, subprocess, urllib.request, urllib.parse
from .schema import categorize, fingerprint, new_finding
from . import env

ZAP_URL = os.environ.get("ZAP_URL", "http://127.0.0.1:8090").rstrip("/")
ZAP_KEY = os.environ.get("ZAP_API_KEY", "sastzapkey")
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


def scan(base_url, findings=None):
    if not _launch():
        print("[!] ZAP 미가용 — 데몬/런처 없음"); return findings or []
    base = base_url.rstrip("/")
    print(f"[*] ZAP DAST: {base}")
    ck = os.environ.get("SAST_HTTP_COOKIE")
    if ck:
        try:
            _api("/JSON/replacer/action/addRule/", description="sast-cookie", enabled="true",
                 matchType="REQ_HEADER", matchRegex="false", matchString="Cookie", replacement=ck)
            print("[*] ZAP: 세션 쿠키 주입")
        except Exception:
            pass
    try:
        _api("/JSON/core/action/accessUrl/", url=base, followRedirects="true", timeout=60)
        sid = _api("/JSON/spider/action/scan/", url=base, recurse="true", maxChildren="0")["scan"]
        _poll("/JSON/spider/view/status/", sid, 300, "spider")
        if os.environ.get("SAST_ZAP_AJAX"):
            print("[*] ZAP: AJAX 스파이더(JS 렌더링)…")
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
    except Exception as e:
        print("[!] ZAP 스캔 예외:", str(e)[:150]); alerts = []
    finally:
        if _started[0]:
            try:
                _api("/JSON/core/action/shutdown/")
            except Exception:
                pass
    new = [_to_finding(a) for a in alerts]
    # 동일 (name,url,param) 중복 제거
    seen, uniq = set(), []
    for f in new:
        if f["fingerprint"] in seen:
            continue
        seen.add(f["fingerprint"]); uniq.append(f)
    print(f"[*] ZAP DAST: alert {len(alerts)} → finding {len(uniq)}건")
    return (findings or []) + uniq


def _to_finding(a):
    name = a.get("name", "ZAP alert")
    cwe = a.get("cweid", "")
    cwe_list = ["CWE-" + str(cwe)] if cwe and cwe != "-1" else []
    cat = categorize(name + " " + a.get("alertRef", ""), cwe_list)
    url = a.get("url", "")
    param = a.get("param", "")
    return new_finding(
        fingerprint=fingerprint("zap-" + str(a.get("pluginId", name)), url, 0, param),
        engines=["zap"], rule=name[:60], full_rule="zap:" + str(a.get("pluginId", "")),
        pack="zap", category=cat, severity=RISK.get(a.get("risk", "Low"), "low"),
        sev_lock=True, confidence=0.85, source="DAST", verdict="true_positive",
        file=url, line=0, cwe=cwe_list,
        message=f"[ZAP] {name} — 파라미터 '{param}'" if param else "[ZAP] " + name,
        evidence=(a.get("evidence") or a.get("attack") or "")[:200],
        poc=(a.get("attack") or "")[:400],
        fix=(a.get("solution") or "")[:400],
        rationale=(a.get("description") or "")[:300])
