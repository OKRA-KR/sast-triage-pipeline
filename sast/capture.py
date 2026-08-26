"""Track C — 패시브 트래픽 분석 (오프라인, 패킷 0).

이미 캡처한 프록시 트래픽(Burp items XML / HAR)을 오프라인으로 파싱해서:
  1) 대상 엔드포인트 전체 식별 → 인벤토리(CSV)
  2) 패시브 룰로 취약점/노출 탐지(보안헤더·쿠키플래그·응답 내 중요정보·URL 내 자격증명·
     verbose 오류·CORS·계정열거 신호·IDOR 후보·CSRF 토큰 부재) — 한 개도 안 쏨
  3) (옵션) 식별된 엔드포인트를 그대로 능동 DAST 에 먹여 정밀 점검(--active, 인가 전용)

폐쇄망 철학: 파싱/룰은 stdlib 만. 캡처는 현장에서 프록시로 이미 확보한 것.
"""
import base64, csv, json, os, re, zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qsl
from .schema import new_finding, fingerprint
from .engines import secrets_engine

# ── 캡처 파서: Burp items XML / HAR → 공통 Exchange 레코드 ──────────────

def _b64(el):
    if el is None or el.text is None:
        return ""
    if el.get("base64") == "true":
        try:
            return base64.b64decode(el.text).decode("utf-8", "replace")
        except Exception:
            return ""
    return el.text


def _split(raw):
    """원시 HTTP 메시지 → (헤더텍스트, 바디)."""
    if "\r\n\r\n" in raw:
        h, b = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        h, b = raw.split("\n\n", 1)
    else:
        h, b = raw, ""
    return h, b


def _headers(htext):
    """헤더 텍스트(첫 줄 제외) → dict(lower). 중복은 리스트로."""
    out = {}
    for line in htext.split("\n")[1:]:
        line = line.rstrip("\r")
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower(); v = v.strip()
        if k in out:
            out[k] = out[k] + "\n" + v
        else:
            out[k] = v
    return out


def _parse_burp(path):
    exs = []
    root = ET.parse(path).getroot()
    for it in root.findall("item"):
        method = (it.findtext("method") or "").strip()
        url = (it.findtext("url") or "").strip()
        req = _b64(it.find("request")); resp = _b64(it.find("response"))
        rqh, rqb = _split(req); rsh, rsb = _split(resp)
        exs.append(_mk(method, url, _headers(rqh), rqb, resp, rsh, rsb,
                       (it.findtext("status") or "").strip(), (it.findtext("mimetype") or "").strip()))
    return exs


def _parse_har(path):
    doc = json.load(open(path, encoding="utf-8"))
    exs = []
    for e in doc.get("log", {}).get("entries", []):
        req = e.get("request", {}); resp = e.get("response", {})
        rqh = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        rsh = {h["name"].lower(): h["value"] for h in resp.get("headers", [])}
        rqb = (req.get("postData") or {}).get("text", "")
        content = resp.get("content", {}) or {}
        rsb = content.get("text", "") or ""
        if content.get("encoding") == "base64" and rsb:
            try:
                rsb = base64.b64decode(rsb).decode("utf-8", "replace")
            except Exception:
                pass
        exs.append(_mk(req.get("method", ""), req.get("url", ""), rqh, rqb, "", "", rsb,
                       str(resp.get("status", "")), content.get("mimeType", "")))
    return exs


def _mk(method, url, rqh, rqb, resp_raw, rsh_text, rsb, status, mime):
    pr = urlparse(url)
    return dict(
        method=(method or "GET").upper(), url=url, host=pr.netloc, path=pr.path or "/",
        query=parse_qsl(pr.query, keep_blank_values=True),
        req_headers=rqh, req_body=rqb,
        status=status, resp_headers=rsh_text, resp_body=rsb, mime=mime,
        scheme=pr.scheme or "https")


def parse(path):
    """확장자/내용으로 Burp XML 또는 HAR 자동 판별."""
    low = path.lower()
    if low.endswith(".har"):
        return _parse_har(path)
    if low.endswith(".saz") or zipfile.is_zipfile(path):
        raise ValueError("SAZ(zip) 캡처는 아직 미지원 — Burp items XML 또는 HAR 로 export")
    head = open(path, "rb").read(256).lstrip()
    if head[:1] == b"{":
        return _parse_har(path)
    return _parse_burp(path)


# ── 요청 바디 파라미터 파싱 (urlencoded / JSON) ──────────────────────

def _body_params(ex):
    ct = (ex["req_headers"].get("content-type") or "").lower()
    body = ex["req_body"] or ""
    params = []
    if "application/json" in ct or body[:1] in ("{", "["):
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                params = [(k, obj[k], "json") for k in obj]
        except Exception:
            pass
    elif "=" in body and len(body) < 4000:
        params = [(k, v, "body") for k, v in parse_qsl(body, keep_blank_values=True)]
    return params


# ── 엔드포인트 인벤토리 ──────────────────────────────────────────────

_IDOR_NAME = re.compile(r"(_sn|_id|_no|_seq|_idx|_num|(^|_)(id|no|seq|idx|uid|sn|num|pk|key))$", re.I)


def endpoints(exs):
    inv = {}
    for ex in exs:
        key = (ex["method"], ex["path"])
        e = inv.setdefault(key, dict(method=ex["method"], path=ex["path"], host=ex["host"],
                                     params={}, statuses=set(), content_types=set(), auth=False,
                                     count=0, sample=ex["url"], state_changing=ex["method"] in
                                     ("POST", "PUT", "DELETE", "PATCH")))
        e["count"] += 1
        if ex["status"]:
            e["statuses"].add(ex["status"])
        if ex["mime"]:
            e["content_types"].add(ex["mime"])
        if ex["req_headers"].get("cookie") or ex["req_headers"].get("authorization"):
            e["auth"] = True
        for k, _ in ex["query"]:
            e["params"].setdefault(k, set()).add("query")
        for k, _v, loc in _body_params(ex):
            e["params"].setdefault(k, set()).add(loc)
    return list(inv.values())


def write_endpoints_csv(inv, path):
    inv = sorted(inv, key=lambda e: (e["path"], e["method"]))
    try:
        fh = open(path, "w", newline="", encoding="utf-8-sig")
    except OSError as e:
        # 파일 잠김(엑셀 등이 열어둠)·권한 문제로 CSV 를 못 써도 스캔 전체를 중단시키지 않는다.
        print(f"[!] endpoints.csv 기록 실패: {e} — 그 파일을 연 프로그램(엑셀 등)을 닫고 재시도. (스캔 결과 자체는 정상 저장)")
        return None
    with fh:
        w = csv.writer(fh)
        w.writerow(["method", "path", "params", "param_locations", "auth_required",
                    "state_changing", "content_types", "statuses", "hits", "sample_url"])
        for e in inv:
            locs = sorted({l for s in e["params"].values() for l in s})
            w.writerow([e["method"], e["path"], "; ".join(sorted(e["params"])), "; ".join(locs),
                        "Y" if e["auth"] else "N", "Y" if e["state_changing"] else "N",
                        "; ".join(sorted(e["content_types"])), "; ".join(sorted(e["statuses"])),
                        e["count"], e["sample"]])
    return path


# ── 패시브 룰 (오프라인, 관측 사실 기반) ─────────────────────────────

_SEC_HEADERS = {
    "content-security-policy": ("security-misconfig", "medium", "CSP 헤더 없음 — XSS/데이터 인젝션 완화 부재"),
    "x-frame-options": ("security-misconfig", "medium", "X-Frame-Options 없음 — 클릭재킹 노출"),
    "x-content-type-options": ("security-misconfig", "low", "X-Content-Type-Options 없음 — MIME 스니핑"),
    "referrer-policy": ("security-misconfig", "low", "Referrer-Policy 없음 — Referer 정보 누출"),
    "strict-transport-security": ("security-misconfig", "medium", "HSTS 없음 — 다운그레이드/스니핑"),
    "permissions-policy": ("security-misconfig", "low", "Permissions-Policy 없음 — 브라우저 기능 제한 부재"),
}
_HTML_ONLY = {"content-security-policy", "x-frame-options", "referrer-policy", "permissions-policy"}

_SQL_ERR = re.compile(r"SQL syntax|mysql_fetch|mysqli|ORA-\d{5}|SQLite3?::|PostgreSQL.*ERROR|"
                      r"Unclosed quotation|Warning: pg_|You have an error in your SQL", re.I)
_STACK = re.compile(r"(Exception in thread|at [a-zA-Z_][\w.]+\([\w.]+:\d+\)|Traceback \(most recent|"
                    r"Fatal error:|Warning: \w+\(\)|Notice: |Stack trace:|\bstacktrace\b)", re.I)
_PATH_DISC = re.compile(r"([A-Za-z]:\\[\w\\]+|/var/www/[\w/]+|/home/\w+/[\w/]+|/usr/local/[\w/]+|/opt/[\w/]+)")
_SENS_URLKEY = re.compile(r"^(pwd|passwd|password|pass|pw|token|secret|api[_-]?key|apikey|"
                          r"access[_-]?token|session|sessionid|otp|auth|jwt|rrn|ssn|card)$", re.I)
_AUTHFAIL = re.compile(r"(비밀번호가?\s*(맞지|틀|일치하지)|존재하지\s*않는\s*(아이디|계정|회원)|"
                       r"등록되지\s*않은|없는\s*아이디|아이디\s*(또는|또넌)\s*비밀번호|"
                       r"incorrect password|wrong password|invalid password|invalid (username|login|credential)|"
                       r"bad credential|authentication failed|login failed|로그인\s*(실패|되지)|"
                       r"user (does not|doesn'?t) exist|no such user|unknown user|access denied)", re.I)
_CSRF_TOKEN = re.compile(r"csrf|xsrf|_token|authenticity|nonce", re.I)


def _agg(cat, sev, rule, title, hits, group_key):
    """같은 유형을 대표 1건으로 집계 (위치 수 + 샘플)."""
    urls = []
    for u in hits:
        if u not in urls:
            urls.append(u)
    n = len(hits)
    sample = " | ".join(urls[:5]) + (f"  (+{len(urls)-5} more)" if len(urls) > 5 else "")
    return new_finding(
        fingerprint=fingerprint("passive-" + rule, group_key, 0, ""),
        engines=["passive"], rule="passive-" + rule, full_rule="passive:" + rule, pack="passive-dast",
        category=cat, severity=sev, sev_lock=True, source="PASSIVE", confidence=0.9,
        verdict="true_positive", file=urls[0] if urls else group_key, line=0,
        message=f"[패시브] {title} — {n}개 응답/위치",
        evidence=f"영향 {n}건 · 샘플: {sample}",
        dynamic={"status": "confirmed", "evidence": f"캡처 트래픽 관측: {title}"},
        rationale="캡처된 실제 트래픽에서 관측된 사실. 능동 요청 없이 확인됨.")


def _cookie_flags(setcookie):
    low = setcookie.lower()
    miss = [f for f, tok in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
            if tok not in low]
    name = setcookie.split("=", 1)[0].strip()
    return name, miss


def passive_scan(exs):
    findings = []
    miss_hdr = {}       # header -> [urls]
    cookie_hits = {}    # (name,flag) -> [urls]
    sqlerr, stack, pathd = [], [], []
    cors_hits, url_cred = [], []
    authfail, idor = [], {}
    csrf_missing = []
    secrets_seen, secrets = set(), []

    for ex in exs:
        rsh = _headers(ex["resp_headers"]) if ex["resp_headers"] else {}
        # HAR 은 resp_headers 를 텍스트로 안 넣음 → dict 직접 처리
        if not rsh and isinstance(ex.get("resp_headers"), str) and not ex["resp_headers"]:
            rsh = {}
        body = ex["resp_body"] or ""
        is_html = "html" in (ex["mime"] or "").lower() or "text/html" in (rsh.get("content-type", ""))
        url = ex["url"]

        # 1) 보안 헤더 부재
        for h, (cat, sev, title) in _SEC_HEADERS.items():
            if h in _HTML_ONLY and not is_html:
                continue
            if h == "strict-transport-security" and ex["scheme"] != "https":
                continue
            if ex["resp_headers"] and h not in rsh:      # 응답 헤더를 실제로 캡처한 경우만
                miss_hdr.setdefault(h, []).append(url)

        # 2) Set-Cookie 플래그
        sc = rsh.get("set-cookie", "")
        for line in sc.split("\n") if sc else []:
            name, miss = _cookie_flags(line)
            for flag in miss:
                cookie_hits.setdefault((name, flag), []).append(url)

        # 3) 응답 본문 중요정보(주민번호·카드·토큰 등) — scan_text 재사용
        if body:
            for f in secrets_engine.scan_text(body, url, source="PASSIVE"):
                k = (f["rule"], f["evidence"])
                if k not in secrets_seen:
                    secrets_seen.add(k); secrets.append(f)

        # 4) URL 쿼리에 자격증명/토큰
        for k, v in ex["query"]:
            if _SENS_URLKEY.match(k):
                url_cred.append(f"{url}  ({k}=…)")

        # 5) verbose 오류/스택/경로 노출
        if body:
            if _SQL_ERR.search(body):
                sqlerr.append(url)
            if _STACK.search(body):
                stack.append(url)
            if _PATH_DISC.search(body):
                pathd.append(url)

        # 6) CORS 오설정
        acao = rsh.get("access-control-allow-origin", "")
        acac = rsh.get("access-control-allow-credentials", "").lower()
        origin = ex["req_headers"].get("origin", "")
        if acao == "*" or (acao and origin and acao == origin):
            if acac == "true" or acao == "*":
                cors_hits.append(f"{url}  (ACAO={acao[:40]}, creds={acac or 'n/a'})")

        # 7) 계정 열거 신호 — 로그인류 응답이 실패 사유를 구체적으로 노출
        if _AUTHFAIL.search(body):
            authfail.append(url)

        # 8) IDOR 후보 — 인증 엔드포인트에서 객체참조성 파라미터(순차/숫자)
        auth = bool(ex["req_headers"].get("cookie") or ex["req_headers"].get("authorization"))
        if auth:
            for name, val, _loc in ([(k, v, "q") for k, v in ex["query"]] +
                                    [(k, v, "b") for k, v, _ in _body_params(ex)]):
                if _IDOR_NAME.search(name) and re.fullmatch(r"\d{1,12}", str(val or "").strip() or "x"):
                    idor.setdefault(name, []).append(f"{ex['method']} {ex['path']}?{name}={val}")

        # 9) 상태변경 POST 에 CSRF 토큰/헤더 부재
        if ex["method"] in ("POST", "PUT", "DELETE", "PATCH") and auth:
            has_tok = bool(_CSRF_TOKEN.search(ex["req_body"] or "")) or \
                      any(_CSRF_TOKEN.search(hn) for hn in ex["req_headers"]) or \
                      "x-requested-with" in ex["req_headers"]
            ct = (ex["req_headers"].get("content-type") or "").lower()
            if not has_tok and ("form-urlencoded" in ct or "application/json" in ct):
                csrf_missing.append(f"{ex['method']} {ex['path']}")

    # ── 집계 → findings ──
    for h, urls in miss_hdr.items():
        cat, sev, title = _SEC_HEADERS[h]
        findings.append(_agg(cat, sev, "missing-header-" + h, title, urls, h))
    for (name, flag), urls in cookie_hits.items():
        findings.append(_agg("insecure-cookie", "medium", "cookie-" + flag.lower(),
                             f"쿠키 '{name}' {flag} 플래그 없음", urls, name + flag))
    if url_cred:
        findings.append(_agg("info-disclosure", "high", "credential-in-url",
                             "URL 쿼리스트링에 자격증명/토큰 노출(로그·Referer 유출)", url_cred, "urlcred"))
    if sqlerr:
        findings.append(_agg("info-disclosure", "high", "sql-error-disclosure",
                             "응답에 SQL 오류 노출(인젝션 정황·DB 정보 유출)", sqlerr, "sqlerr"))
    if stack:
        findings.append(_agg("info-disclosure", "medium", "stacktrace-disclosure",
                             "응답에 스택트레이스/디버그 오류 노출", stack, "stack"))
    if pathd:
        findings.append(_agg("info-disclosure", "low", "path-disclosure",
                             "응답에 서버 내부 경로 노출", pathd, "pathd"))
    if cors_hits:
        findings.append(_agg("security-misconfig", "high", "cors-permissive",
                             "관대한 CORS(자격증명 허용/와일드카드)", cors_hits, "cors"))
    if authfail:
        f = _agg("user-enumeration", "medium", "user-enumeration",
                 "로그인 실패 사유가 구체적 → 계정 열거 가능", authfail, "userenum")
        f["verdict"] = "needs_review"; f["confidence"] = 0.6
        f["rationale"] = "실패 응답이 아이디/비밀번호를 구분해 노출하면 유효 계정 열거 가능. 유효 vs 무효 계정 응답 비교로 확증 필요."
        findings.append(f)
    for name, hits in idor.items():
        f = _agg("idor", "medium", "idor-candidate-" + name,
                 f"객체참조 파라미터 '{name}'(순차/숫자) — IDOR 후보", hits, "idor" + name)
        f["verdict"] = "needs_review"; f["confidence"] = 0.5
        f["rationale"] = f"인증 상태에서 '{name}' 값이 순차/숫자. 값 변경 시 타 사용자/법인 리소스 접근되는지 수동 검증 필요(권한검증)."
        findings.append(f)
    if csrf_missing:
        f = _agg("csrf", "medium", "missing-csrf-token",
                 "상태변경 요청에 CSRF 토큰/헤더 부재", csrf_missing, "csrf")
        f["verdict"] = "needs_review"; f["confidence"] = 0.6
        findings.append(f)

    return findings + secrets


def cookie_from(exs):
    """캡처에서 가장 흔한 Cookie 헤더 추출 — 능동 점검 인증에 재사용."""
    from collections import Counter
    c = Counter(ex["req_headers"].get("cookie", "") for ex in exs if ex["req_headers"].get("cookie"))
    return c.most_common(1)[0][0] if c else ""
