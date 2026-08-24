"""Track B — 블랙박스 점검 (Repo 를 못 받은 경우: 엔드포인트 식별 → 공격 가능 포인트).

소스가 없을 때 라이브 URL 만으로 수행하는 능동 점검(stdlib urllib, GET 전용, 안전).
LLM 불필요 — 내부망/폐쇄망의 인가 대상에도 사용 가능(외부 인터넷 아님).
Track A(SAST) 결과가 있으면 정적 finding 과 라이브 헤더를 교차연계(IAST 스타일)도 한다.
심화 능동 확증(SQLi PoC 재현 등)은 3계층(LLM) 또는 확장 슬롯.
"""
import os, ssl, urllib.request, urllib.error
from .schema import new_finding
from . import env

TIMEOUT = 6
UA = "sast-blackbox/1"

SEC_HEADERS = [
    ("content-security-policy", "CSP 미설정", "security-misconfig", "medium"),
    ("x-frame-options", "클릭재킹 방어(X-Frame-Options) 미설정", "security-misconfig", "medium"),
    ("x-content-type-options", "MIME 스니핑 방어(nosniff) 미설정", "security-misconfig", "low"),
    ("strict-transport-security", "HSTS 미설정", "security-misconfig", "low"),
    ("referrer-policy", "Referrer-Policy 미설정", "security-misconfig", "low"),
]
# (경로, 라벨, 심각도, 본문시그니처) — 200 + 시그니처 일치해야 노출로 확증(오탐 억제)
EXPOSED = [
    ("/.git/HEAD", "Git 저장소 노출", "high", "ref:"),
    ("/actuator/env", "Spring Actuator env 노출", "high", "propertysources"),
    ("/actuator/health", "Spring Actuator health 노출", "medium", "status"),
    ("/actuator/mappings", "Spring Actuator mappings 노출", "medium", "_links"),
    ("/metrics", "메트릭 엔드포인트 노출", "medium", "# help"),
    ("/v3/api-docs", "OpenAPI 문서 노출", "low", "openapi"),
    ("/swagger-ui/index.html", "Swagger UI 노출", "low", "swagger"),
    ("/server-status", "Apache 서버상태 노출", "medium", "server status"),
]
HEADER_KEYWORDS = [
    (("nosniff", "x_content", "content-type-options"), "x-content-type-options"),
    (("frame", "clickjack"), "x-frame-options"),
    (("csp", "content-security"), "content-security-policy"),
    (("hsts", "strict-transport"), "strict-transport-security"),
]


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _fetch(url):
    req = urllib.request.Request(url, headers=env.http_headers())
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            body = r.read(4096).decode("utf-8", "replace")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception:
        return None, {}, ""


def probe(findings, base_url):
    base = base_url.rstrip("/")
    status, headers, _ = _fetch(base + "/")
    if status is None:
        print(f"[!] 블랙박스: {base} 응답 없음 — 건너뜀")
        return findings
    print(f"[*] 블랙박스(엔드포인트 점검): {base} 라이브 확인 (status {status})")
    added = []
    for h, label, cat, sev in SEC_HEADERS:
        if h not in headers:
            added.append(new_finding(
                fingerprint="bb-hdr-" + h, engines=["blackbox"], rule="missing-" + h,
                full_rule="missing-" + h, pack="blackbox", category=cat, severity=sev, sev_lock=True,
                source="DAST", verdict="true_positive", confidence=0.9, file=base + "/",
                message=label + " (라이브 확인)", evidence=f"GET / 응답 헤더에 {h} 없음",
                dynamic={"status": "confirmed", "evidence": f"응답에 {h} 헤더 없음"}))
    for h in ("server", "x-powered-by"):
        if headers.get(h):
            added.append(new_finding(
                fingerprint="bb-disc-" + h, engines=["blackbox"], rule=h + "-disclosure",
                full_rule=h + "-disclosure", pack="blackbox", category="info-disclosure",
                severity="low", sev_lock=True, source="DAST", verdict="true_positive",
                confidence=0.9, file=base + "/",
                message=f"{h} 헤더로 기술스택 노출: {headers[h]}", evidence=f"{h}: {headers[h]}",
                dynamic={"status": "confirmed", "evidence": f"{h}: {headers[h]}"}))
    for path, label, sev, sig in EXPOSED:
        st, _, bd = _fetch(base + path)
        if st == 200 and sig in (bd or "").lower():
            added.append(new_finding(
                fingerprint="bb-exp-" + path, engines=["blackbox"], rule="exposed" + path.replace("/", "-"),
                full_rule="exposed:" + path, pack="blackbox", category="info-disclosure",
                severity=sev, sev_lock=True, source="DAST", verdict="true_positive",
                confidence=0.95, file=base + path, message=label + " (라이브 200 응답)",
                evidence=f"GET {path} → 200, 시그니처 '{sig}' 확인",
                dynamic={"status": "confirmed", "evidence": f"{path} 200 노출"}))
    # 정적(Track A) finding ↔ 라이브 헤더 교차연계
    xconfirm = xrefute = 0
    for f in findings:
        if f.get("suppressed") or f["category"] not in ("security-misconfig", "insecure-cookie", "info-disclosure"):
            continue
        r = (f.get("rule", "") + " " + f.get("message", "")).lower()
        for keys, hdr in HEADER_KEYWORDS:
            if any(k in r for k in keys):
                if hdr in headers:
                    f["dynamic"] = {"status": "refuted", "evidence": f"라이브 응답에 {hdr} 존재({headers[hdr][:40]})"}
                    f["rationale"] = (f.get("rationale") or "") + f"[블랙박스] 라이브엔 {hdr} 설정됨 — 우선순위 낮음."
                    xrefute += 1
                else:
                    f["dynamic"] = {"status": "confirmed", "evidence": f"라이브 응답에 {hdr} 없음"}
                    f["verdict"] = "true_positive"
                    f["rationale"] = (f.get("rationale") or "") + f"[블랙박스] 라이브에서 {hdr} 부재 확인."
                    xconfirm += 1
                break
    if added or xconfirm or xrefute:
        print(f"[*] 블랙박스: 라이브 노출 {len(added)}건 · 정적확증 {xconfirm} · 정적반증 {xrefute}")
    return findings + added
