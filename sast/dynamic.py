"""3계층 — 동적 검증 / DAST 브릿지 (stdlib urllib, 외부 의존성 없음).

라이브 URL 이 주어질 때만(--verify 또는 SAST_VERIFY_URL) 켜진다. 안전을 위해 GET 전용 —
인젝션 페이로드는 쓰지 않는다(런타임 노출·설정 확인 + 정적 finding 과 헤더 교차연계).
심화 능동 확증(SQLi 등 PoC 재현)은 확장 슬롯으로 남긴다. 끄기: SAST_NO_VERIFY=1.
"""
import os, ssl, urllib.request, urllib.error
from .schema import new_finding

TIMEOUT = 6
UA = "sast-dast-bridge/1"

# (헤더, 라벨, 카테고리, 심각도) — 응답에 없으면 런타임 미설정으로 확증
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

# 정적 finding 룰 키워드 → 라이브에서 확인할 헤더 (교차연계, IAST 스타일)
HEADER_KEYWORDS = [
    (("nosniff", "x_content", "content-type-options"), "x-content-type-options"),
    (("frame", "clickjack"), "x-frame-options"),
    (("csp", "content-security"), "content-security-policy"),
    (("hsts", "strict-transport"), "strict-transport-security"),
]


def _ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE   # 로컬 self-signed 허용
    return c


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            body = r.read(4096).decode("utf-8", "replace")
            return r.status, {k.lower(): v for k, v in r.headers.items()}, body
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
    except Exception:
        return None, {}, ""


def verify(findings, base_url):
    base = base_url.rstrip("/")
    status, headers, _ = _fetch(base + "/")
    if status is None:
        print(f"[!] 3계층: {base} 응답 없음 — 동적검증 건너뜀")
        return findings
    print(f"[*] 3계층(DAST): {base} 라이브 확인 (status {status})")
    added = []

    # 1) 보안 헤더 미설정 확증
    for h, label, cat, sev in SEC_HEADERS:
        if h not in headers:
            added.append(new_finding(
                fingerprint="dast-hdr-" + h, engines=["dast"], rule="missing-" + h,
                full_rule="missing-" + h, pack="dast", category=cat, severity=sev, sev_lock=True,
                source="DAST", verdict="true_positive", confidence=0.9, file=base + "/",
                message=label + " (라이브 확인)", evidence=f"GET / 응답 헤더에 {h} 없음",
                dynamic={"status": "confirmed", "evidence": f"응답에 {h} 헤더 없음"}))

    # 기술스택 노출 헤더
    for h in ("server", "x-powered-by"):
        if headers.get(h):
            added.append(new_finding(
                fingerprint="dast-disc-" + h, engines=["dast"], rule=h + "-disclosure",
                full_rule=h + "-disclosure", pack="dast", category="info-disclosure",
                severity="low", sev_lock=True, source="DAST", verdict="true_positive",
                confidence=0.9, file=base + "/",
                message=f"{h} 헤더로 기술스택 노출: {headers[h]}", evidence=f"{h}: {headers[h]}",
                dynamic={"status": "confirmed", "evidence": f"{h}: {headers[h]}"}))

    # 2) 민감 경로 노출 프로브 (시그니처 확인으로 오탐 억제)
    for path, label, sev, sig in EXPOSED:
        st, _, bd = _fetch(base + path)
        if st == 200 and sig in (bd or "").lower():
            added.append(new_finding(
                fingerprint="dast-exp-" + path, engines=["dast"], rule="exposed" + path.replace("/", "-"),
                full_rule="exposed:" + path, pack="dast", category="info-disclosure",
                severity=sev, sev_lock=True, source="DAST", verdict="true_positive",
                confidence=0.95, file=base + path, message=label + " (라이브 200 응답)",
                evidence=f"GET {path} → 200, 시그니처 '{sig}' 확인",
                dynamic={"status": "confirmed", "evidence": f"{path} 200 노출"}))

    # 3) 정적 finding ↔ 라이브 헤더 교차연계 (IAST 스타일: 확증/반증)
    xconfirm = xrefute = 0
    for f in findings:
        if f.get("suppressed") or f["category"] not in ("security-misconfig", "insecure-cookie", "info-disclosure"):
            continue
        r = (f.get("rule", "") + " " + f.get("message", "")).lower()
        for keys, hdr in HEADER_KEYWORDS:
            if any(k in r for k in keys):
                if hdr in headers:   # 라이브엔 헤더 있음 → 정적 지적이 이미 완화됨
                    f["dynamic"] = {"status": "refuted", "evidence": f"라이브 응답에 {hdr} 존재({headers[hdr][:40]})"}
                    f["rationale"] = (f.get("rationale") or "") + f"[동적] 라이브엔 {hdr} 설정됨 — 우선순위 낮음."
                    xrefute += 1
                else:                # 정적 지적을 라이브가 확증
                    f["dynamic"] = {"status": "confirmed", "evidence": f"라이브 응답에 {hdr} 없음"}
                    f["verdict"] = "true_positive"
                    f["rationale"] = (f.get("rationale") or "") + f"[동적] 라이브에서 {hdr} 부재 확인."
                    xconfirm += 1
                break

    if added or xconfirm or xrefute:
        print(f"[*] 3계층: 라이브 노출 {len(added)}건 · 정적확증 {xconfirm} · 정적반증 {xrefute}")
    return findings + added
