"""캡처 기반 능동 검증 (replay) — 진짜 인증 요청을 재전송하며 표적 변형.

blind 스캐너(ZAP 스파이더)의 한계: 인증 세션·정확한 바디 파라미터를 몰라
POST API 를 유효하게 못 때린다. 캡처에는 그 모든 게 있으므로, **실제 요청을
baseline 으로 재전송**하고 파라미터 하나만 변형해 확증한다:
  - SQLi   : 값 + `'`(오류) / 불리언 참·거짓 응답차
  - XSS    : 마커 반사(미이스케이프)
  - 권한검증(IDOR/BOLA): 객체참조 파라미터(corp_sn 등)를 남의 id 로 바꿔
             같은 세션으로 접근 → 200+데이터면 접근통제 실패. (무효 id 대조로 오탐↓)

패킷 전송 → 인가 대상 전용. 캡처의 세션 쿠키(또는 SAST_HTTP_COOKIE)를 그대로 사용.
비파괴 payload 만(RCE/파일쓰기 없음). 상태변경(POST save 등)은 IDOR 은 읽기형만 시도.
"""
import json, os, re, ssl, time, urllib.request, urllib.error
from urllib.parse import urlparse, parse_qsl, urlencode
from .schema import new_finding
from .capture import _SQL_ERR, _IDOR_NAME, _body_params, _headers
from . import env

TIMEOUT = 10
MAX_REQ = int(os.environ.get("SAST_REPLAY_REQ", "600"))
DELAY = float(os.environ.get("SAST_REPLAY_DELAY", "0.05"))
XSS_MARK = "okr7xq<z>"
_LOGIN_SIG = re.compile(r"(login|signin|로그인|비밀번호|아이디를?\s*입력|인증이?\s*필요)", re.I)
_DROP_H = {"content-length", "host", "connection", "accept-encoding", "if-modified-since",
           "if-none-match", "cookie" if os.environ.get("SAST_HTTP_COOKIE") else ""}
_req = [0]


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def _send(method, url, headers, body):
    if _req[0] >= MAX_REQ:
        return None
    _req[0] += 1
    time.sleep(DELAY)
    data = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={k: v for k, v in headers.items() if k})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_ctx()) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(300000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (e.read(80000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None


def _headers_for(ex):
    h = {k: v for k, v in ex["req_headers"].items() if k not in _DROP_H}
    ck = os.environ.get("SAST_HTTP_COOKIE")
    if ck:
        h["Cookie"] = ck
    return h


def _params(ex):
    """(key, value, loc) — loc in {query, body, json}."""
    out = [(k, v, "query") for k, v in ex["query"]]
    out += [(k, v, loc) for k, v, loc in _body_params(ex)]
    return out


def _mutate(ex, key, loc, newval):
    """해당 파라미터만 newval 로 바꾼 (url, body) 재구성. 나머지는 캡처 원본값 유지."""
    pr = urlparse(ex["url"])
    q = dict(parse_qsl(pr.query, keep_blank_values=True))
    body = ex["req_body"] or ""
    ct = (ex["req_headers"].get("content-type") or "").lower()
    if loc == "query":
        q[key] = newval
        url = pr._replace(query=urlencode(q)).geturl(); return url, body
    url = pr._replace(query=urlencode(q)).geturl() if q else ex["url"]
    if loc == "json" or "application/json" in ct:
        try:
            obj = json.loads(body); obj[key] = newval; return url, json.dumps(obj)
        except Exception:
            return url, body
    bd = dict(parse_qsl(body, keep_blank_values=True)); bd[key] = newval
    return url, urlencode(bd)


def _resp_len(r):
    return len(r[2]) if r else 0


def _blocked(r):
    """접근 차단(정상 authz) 신호: 403/401, 로그인 리다이렉트, 로그인 화면."""
    if not r:
        return True
    if r[0] in (401, 403):
        return True
    loc = r[1].get("location", "")
    if 300 <= r[0] < 400 and _LOGIN_SIG.search(loc):
        return True
    if _LOGIN_SIG.search(r[2][:2000]):
        return True
    return False


def scan_capture(exchanges):
    base_hosts = {ex["host"] for ex in exchanges if ex["host"]}
    print(f"[*] replay 검증: 캡처 {len(exchanges)}건 · 호스트 {', '.join(sorted(base_hosts))} (인가 대상 전제·비파괴)")
    seen, reps = set(), []
    for ex in exchanges:
        sig = (ex["method"], ex["path"], tuple(sorted(k for k, _, _ in _params(ex))))
        if sig in seen or not ex["url"].startswith("http"):
            continue
        seen.add(sig); reps.append(ex)

    findings, seen_f = [], set()

    def add(f):
        k = (f["rule"], f["file"], f.get("evidence", "")[:40])
        if k not in seen_f:
            seen_f.add(k); findings.append(f)

    for ex in reps:
        hdr = _headers_for(ex)
        base = _send(ex["method"], ex["url"], hdr, ex["req_body"] or None)
        if not base:
            continue
        bl = _resp_len(base)
        for key, val, loc in _params(ex):
            val = val or "1"
            # ── SQLi: 오류 시그니처 ──
            u, b = _mutate(ex, key, loc, val + "'")
            r = _send(ex["method"], u, hdr, b)
            if r and _SQL_ERR.search(r[2]) and not _SQL_ERR.search(base[2]):
                add(_f("sql-injection", "critical", ex, key, val + "'",
                       "SQL 오류 시그니처 반사", "true_positive"))
                continue
            # ── SQLi: 불리언 응답차 ──
            ut, bt = _mutate(ex, key, loc, val + "' AND '1'='1")
            uf, bf = _mutate(ex, key, loc, val + "' AND '1'='2")
            rt, rf = _send(ex["method"], ut, hdr, bt), _send(ex["method"], uf, hdr, bf)
            if rt and rf:
                lt, lf = _resp_len(rt), _resp_len(rf)
                if abs(lt - bl) < max(20, 0.02 * bl) and abs(lf - lt) > max(60, 0.08 * max(lt, 1)):
                    add(_f("sql-injection", "critical", ex, key, "' AND '1'='1 vs '2",
                           f"불리언 응답차(base {bl}·true {lt}·false {lf})", "true_positive"))
            # ── XSS: 마커 반사 ──
            ux, bx = _mutate(ex, key, loc, XSS_MARK)
            rx = _send(ex["method"], ux, hdr, bx)
            if rx and XSS_MARK in rx[2]:
                add(_f("xss", "high", ex, key, XSS_MARK, "마커 미이스케이프 반사", "true_positive"))
            # ── 권한검증(IDOR): 객체참조 파라미터를 남의 id 로 ──
            if _IDOR_NAME.search(key) and re.fullmatch(r"\d{1,12}", str(val).strip()):
                iv = int(val)
                other = str(iv + 1 if iv != 1 else 2)
                ctrl = "987654321"
                uo, bo = _mutate(ex, key, loc, other)
                uc, bc = _mutate(ex, key, loc, ctrl)
                ro, rc = _send(ex["method"], uo, hdr, bo), _send(ex["method"], uc, hdr, bc)
                if ro and not _blocked(ro) and 200 <= ro[0] < 300:
                    lo, lc = _resp_len(ro), _resp_len(rc)
                    # 남의 id 는 데이터형 응답, 무효 id 는 빈/오류 → 실제 레코드 접근 정황
                    if lo > 50 and (not rc or abs(lo - lc) > max(40, 0.1 * lo)):
                        f = _f("idor", "high", ex, key, f"{key}={other}",
                               f"타 객체 id 접근 200+데이터(base {bl}·other {lo}·invalid {lc}) · 로그인/403 미발생",
                               "needs_review")
                        f["confidence"] = 0.65
                        f["rationale"] = ("동일 세션으로 남의 객체 id 응답이 데이터형(200)이고 무효 id 와 다름 → "
                                          "객체수준 접근통제(BOLA/IDOR) 실패 정황. 두 계정으로 교차 확증 권장.")
                        add(f)
    print(f"[*] replay 검증: 요청 {_req[0]}건 · 확증/후보 {len(findings)}건")
    return findings


def _f(cat, sev, ex, key, payload, ev, verdict):
    loc = f"{ex['method']} {ex['path']}"
    return new_finding(
        fingerprint="replay-" + cat + "-" + re.sub(r"\W+", "", ex["path"])[-30:] + "-" + key,
        engines=["replay"], rule="replay-" + cat, full_rule="replay:" + cat, pack="replay-dast",
        category=cat, severity=sev, sev_lock=True, source="DAST", verdict=verdict, confidence=0.9,
        file=ex["url"].split("?")[0], line=0,
        message=f"[replay] {cat} — {loc} 파라미터 '{key}': {ev}",
        evidence=f"payload={payload} → {ev}",
        poc=f"{loc}  {key}={payload}  (캡처 세션 재전송)",
        dynamic={"status": "confirmed" if verdict == "true_positive" else "candidate", "evidence": ev})
