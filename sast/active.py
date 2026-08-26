"""능동 DAST — URL 기반 취약점 점검 (Track B 능동 모드).

인가된 대상 전용(--active). stdlib urllib 만, 비파괴 탐지 payload 만 사용
(RCE/파일쓰기 등 파괴형 제외). 크롤 → 파라미터/폼 수집 → 탐지 payload 주입 →
응답 시그니처(오류/반사/평가/리다이렉트)로 확증. 레이트리밋·요청상한·동일호스트 한정.

끄기: 기본 off. 켜기: --active (또는 SAST_ACTIVE=1) + --verify <URL>.
"""
import os, re, ssl, time, urllib.request, urllib.error
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse
from .schema import new_finding
from . import env

# 인증 없이도 자주 존재하는 표면 — 크롤 시드용 콘텐츠 발굴(경량)
COMMON_PATHS = ["/robots.txt", "/sitemap.xml", "/api", "/api/", "/admin", "/login",
                "/user", "/search", "/index.php", "/main", "/home", "/config", "/upload",
                "/board", "/list", "/view", "/download", "/file", "/mypage", "/member"]
# JS/HTML 에서 엔드포인트 문자열 추출
_EP_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{2,60}(?:\?[a-zA-Z0-9_=&%\-]{1,60})?)["']""")

TIMEOUT = 8
UA = "sast-active-dast/1"
MARK = "zqx9k7"                       # 반사 탐지 마커
MAX_PAGES = int(os.environ.get("SAST_ACTIVE_PAGES", "40"))
MAX_REQ = int(os.environ.get("SAST_ACTIVE_REQ", "800"))
DELAY = float(os.environ.get("SAST_ACTIVE_DELAY", "0.05"))

SQL_ERR = re.compile(r"SQL syntax|mysql_fetch|ORA-\d{5}|SQLite/|PostgreSQL.*ERROR|"
                     r"Unclosed quotation|quoted string not properly|"
                     r"you have an error in your sql", re.I)
_req_count = [0]
truncated = [False]     # 요청 상한 도달로 부분 스캔 여부
_warned = [False]


def _ctx():
    return env.ssl_context()     # 기본 검증 on, SAST_INSECURE_TLS=1 시에만 비활성


def _fetch(url, redirect=True, data=None):
    if _req_count[0] >= MAX_REQ:
        if not _warned[0]:
            print(f"[!] 요청 상한 {MAX_REQ} 도달 — 이후 프로브 생략, 결과 부분적(SAST_ACTIVE_REQ 로 상향)")
            _warned[0] = True; truncated[0] = True
        return None
    _req_count[0] += 1
    time.sleep(DELAY)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    op = urllib.request.build_opener() if redirect else urllib.request.build_opener(_NoRedirect)
    body = urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=env.http_headers())
    try:
        with op.open(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (e.read(50000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None


# SPA 자율탐색 — JS 에서 API 엔드포인트 추출
_JS_CALL = re.compile(r"""(?:fetch|axios(?:\.\w+)?|\.ajax|\.(?:get|post|put|delete|patch)|open|url\s*[:=])\s*\(?\s*["'`]([^"'`]{2,120})["'`]""", re.I)
_JS_URL = re.compile(r"""["'`](/(?:api|rest|graphql|ajax|service|services|backend|internal|v\d)[a-zA-Z0-9_\-./]{0,80}(?:\?[a-zA-Z0-9_=&%.\-]{0,80})?)["'`]""")
MAX_JS = int(os.environ.get("SAST_ACTIVE_JS", "20"))


def _extract_js_endpoints(js, origin, host):
    """JS 텍스트에서 API 엔드포인트(URL/경로) 추출 — SPA 의 fetch/axios/ajax 호출·경로 리터럴."""
    found = set()
    for rx in (_JS_CALL, _JS_URL):
        for m in rx.findall(js or ""):
            if m.startswith("http"):
                u = m
            elif m.startswith("/"):
                u = origin + m
            else:
                continue
            if urlparse(u).netloc and urlparse(u).netloc != host:
                continue           # 외부 도메인 제외(동일 호스트만)
            found.add(u.split("#")[0])
    return found


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self.forms = []; self.scripts = []; self._f = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])            # SPA JS 번들
        elif tag == "form":
            self._f = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "fields": []}
        elif tag in ("input", "textarea", "select") and self._f is not None and a.get("name"):
            self._f["fields"].append(a["name"])
    def handle_endtag(self, tag):
        if tag == "form" and self._f is not None:
            self.forms.append(self._f); self._f = None


def _crawl(base):
    host = urlparse(base).netloc
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base))
    seen, pages, forms, seen_js = set(), [], [], set()
    js_eps = 0
    queue = [base] + [origin + p for p in COMMON_PATHS]     # 콘텐츠 발굴 시드
    while queue and len(seen) < MAX_PAGES:
        url = queue.pop(0).split("#")[0]
        if url in seen:
            continue
        seen.add(url)
        r = _fetch(url)
        if not r or r[0] == 404 or not r[2]:
            continue
        pages.append(url)
        p = _Links()
        try:
            p.feed(r[2])
        except Exception:
            pass
        for f in p.forms:
            f["page"] = url; forms.append(f)
        cand = list(p.links) + [urljoin(url, a) for a in (f["action"] for f in p.forms) if a]
        cand += _EP_RE.findall(r[2])                        # HTML/인라인 JS 내 엔드포인트 문자열
        cand += list(_extract_js_endpoints(r[2], origin, host))   # 인라인 JS API 호출
        # SPA: <script src> JS 번들을 받아 API 엔드포인트 추출
        for s in getattr(p, "scripts", []):
            su = urljoin(url, s).split("#")[0]
            if (urlparse(su).netloc == host and ".js" in su.lower()
                    and su not in seen_js and len(seen_js) < MAX_JS):
                seen_js.add(su)
                jr = _fetch(su)
                if jr and jr[2]:
                    eps = _extract_js_endpoints(jr[2], origin, host)
                    js_eps += len(eps); cand += list(eps)
        for href in cand:
            u = urljoin(url, href).split("#")[0]
            if urlparse(u).netloc == host and u not in seen and len(seen) + len(queue) < MAX_PAGES * 3:
                queue.append(u)
    if seen_js:
        print(f"[*] SPA 자율탐색: JS {len(seen_js)}개 분석 · API 엔드포인트 {js_eps}개 추출")
    return pages, forms


def _set_param(url, key, val):
    pr = urlparse(url)
    q = dict(parse_qsl(pr.query, keep_blank_values=True)); q[key] = val
    return urlunparse(pr._replace(query=urlencode(q)))


# (category, payload, severity, detector) — detector(baseline_body, probe_status, probe_headers, probe_body)->evidence|None
def _det_sqli(b, st, h, body):
    if SQL_ERR.search(body) and not SQL_ERR.search(b or ""):
        return "SQL 오류 시그니처 반사"
    return None
def _det_ssti(b, st, h, body):
    return "산술 평가됨(xx49yy)" if "xx49yy" in body else None
def _det_xss(b, st, h, body):
    return "마커 미이스케이프 반사(<%s>)" % MARK if ("<%s>" % MARK) in body else None
def _det_lfi(b, st, h, body):
    return "/etc/passwd 내용 반환" if re.search(r"root:.*:0:0:", body) else None
def _det_redirect(b, st, h, body):
    loc = (h or {}).get("location", "")
    return "외부 리다이렉트 Location=%s" % loc[:60] if st and 300 <= st < 400 and "evil.example" in loc else None

PROBES = [
    ("sql-injection", "'", "critical", _det_sqli),
    ("ssti", "xx{{7*7}}yy", "critical", _det_ssti),
    ("xss", "<%s>" % MARK, "high", _det_xss),
    ("path-traversal", "../../../../etc/passwd", "high", _det_lfi),
    ("open-redirect", "https://evil.example/", "medium", _det_redirect),
]


def _probe_point(fetch_with):
    """fetch_with(payload)->resp ; baseline 은 정상값."""
    out = []
    base = fetch_with(MARK + "1")
    base_body = base[2] if base else ""
    for cat, payload, sev, det in PROBES:
        r = fetch_with(payload) if cat != "open-redirect" else fetch_with(payload, redirect=False)
        if not r:
            continue
        ev = det(base_body, r[0], r[1], r[2])
        if ev:
            out.append((cat, sev, payload, ev))
    # 불리언 기반 SQLi(오류 안 뱉는 경우) — true≈baseline, false 는 응답차
    t = fetch_with("1' AND '1'='1"); fa = fetch_with("1' AND '1'='2")
    if t and fa and t[2] and fa[2] and base_body:
        lb, lt, lf = len(base_body), len(t[2]), len(fa[2])
        if abs(lt - lb) < max(20, 0.02 * lb) and abs(lf - lt) > max(40, 0.06 * lt):
            out.append(("sql-injection", "critical", "' AND '1'='1 vs '2",
                        "불리언 응답차(base %d · true %d · false %d)" % (lb, lt, lf)))
    return out


def _to_exchanges(pages, forms):
    """크롤로 식별한 페이지/폼 → capture 공통 Exchange 리스트 (replay/인벤토리 공용).
    쿠키(SAST_HTTP_COOKIE)가 있으면 실어 '인증된 요청'으로 만든다(무인증 스윕이 이걸 벗겨 테스트)."""
    from . import capture
    ck = os.environ.get("SAST_HTTP_COOKIE")
    base_h = {"cookie": ck} if ck else {}
    exs = []
    for u in pages:
        exs.append(capture._mk("GET", u, dict(base_h), "", "", "", "", "", ""))
    for f in forms:
        action = urljoin(f["page"], f.get("action") or f["page"])
        method = (f.get("method") or "get").upper()
        fields = f.get("fields") or []
        if method == "GET":
            url = action + ("?" + "&".join(k + "=" for k in fields) if fields else "")
            exs.append(capture._mk("GET", url, dict(base_h), "", "", "", "", "", ""))
        else:
            h = dict(base_h); h["content-type"] = "application/x-www-form-urlencoded"
            body = "&".join(k + "=" for k in fields)
            exs.append(capture._mk("POST", action, h, body, "", "", "", "", ""))
    return exs


def crawl_exchanges(base_url):
    """URL 크롤 → (exchanges, 페이지수, 폼수). URL 을 replay role 엔진에 먹이기 위한 진입점."""
    base = base_url.rstrip("/")
    print(f"[*] URL 크롤(엔드포인트 식별): {base}")
    pages, forms = _crawl(base)
    return _to_exchanges(pages, forms), len(pages), len(forms)


def _write_endpoints(pages, forms, out_dir):
    """크롤로 식별한 페이지/폼 → 엔드포인트 인벤토리 CSV (캡처와 동일 포맷)."""
    if not out_dir:
        return
    from . import capture
    inv = capture.endpoints(_to_exchanges(pages, forms))
    capture.write_endpoints_csv(inv, os.path.join(out_dir, "endpoints.csv"))
    print(f"[*] 능동 크롤: 엔드포인트 {len(inv)}개 식별 → {out_dir}/endpoints.csv")


def scan(base_url, out_dir=None):
    base = base_url.rstrip("/")
    print(f"[*] 능동 DAST: {base} (인가 대상 전제 · 비파괴 payload)")
    pages, forms = _crawl(base)
    _write_endpoints(pages, forms, out_dir)     # URL → 엔드포인트 식별부터
    findings = []
    seen_pt = set()

    # 1) URL 쿼리 파라미터
    for url in pages:
        params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        for key in params:
            pt = (urlparse(url).path, key)
            if pt in seen_pt:
                continue
            seen_pt.add(pt)
            def fw(pay, redirect=True, u=url, k=key):
                return _fetch(_set_param(u, k, pay), redirect=redirect)
            for cat, sev, payload, ev in _probe_point(fw):
                findings.append(_finding(cat, sev, url, key, payload, ev))

    # 2) 폼 필드 (GET/POST — method 존중)
    for f in forms:
        action = urljoin(f["page"], f["action"] or f["page"])
        is_post = f.get("method") == "post"
        for key in f["fields"]:
            def fw(pay, redirect=True, a=action, fields=f["fields"], k=key, post=is_post):
                data = {fld: (pay if fld == k else "test") for fld in fields}
                if post:
                    return _fetch(a, redirect=redirect, data=data)
                return _fetch(a + ("?" + urlencode(data)), redirect=redirect)
            for cat, sev, payload, ev in _probe_point(fw):
                findings.append(_finding(cat, sev, action, key, payload, ev, form=True))

    print(f"[*] 능동 DAST: 요청 {_req_count[0]}건 · 페이지 {len(pages)} · 폼 {len(forms)} · 확증 {len(findings)}건")
    return findings


def scan_endpoints(base_url, eps):
    """패시브로 식별한 엔드포인트(메서드+경로+파라미터)를 직접 겨냥한 정밀 능동 점검.
    blind 크롤 대신 실제 파라미터에만 payload 주입 → 정밀도↑ 요청수↓. 인가 대상 전용."""
    origin = "{0.scheme}://{0.netloc}".format(urlparse(base_url))
    print(f"[*] 능동 DAST(엔드포인트 타깃): {origin} · 엔드포인트 {len(eps)}개")
    findings, seen_pt = [], set()
    for e in eps:
        url = origin + e["path"]
        post = e["method"] in ("POST", "PUT", "PATCH")
        for key, locs in e["params"].items():
            pt = (e["method"], e["path"], key)
            if pt in seen_pt:
                continue
            seen_pt.add(pt)
            names = list(e["params"].keys())
            def fw(pay, redirect=True, u=url, k=key, names=names, post=post):
                data = {n: (pay if n == k else "1") for n in names}
                if post:
                    return _fetch(u, redirect=redirect, data=data)
                return _fetch(u + "?" + urlencode(data), redirect=redirect)
            for cat, sev, payload, ev in _probe_point(fw):
                findings.append(_finding(cat, sev, url + f" [{e['method']}]", key, payload, ev, form=post))
    print(f"[*] 능동 DAST(타깃): 요청 {_req_count[0]}건 · 확증 {len(findings)}건")
    return findings


def _finding(cat, sev, url, param, payload, ev, form=False):
    return new_finding(
        fingerprint="dast-active-" + cat + "-" + re.sub(r"\W+", "", url)[-30:] + "-" + param,
        engines=["active-dast"], rule="active-" + cat, full_rule="active:" + cat, pack="active-dast",
        category=cat, severity=sev, sev_lock=True, source="DAST", verdict="true_positive",
        confidence=0.9, file=url, line=0,
        message=f"[능동] {cat} 확증 — 파라미터 '{param}'{'(form)' if form else ''}: {ev}",
        evidence=f"payload={payload} → {ev}",
        poc=f"{url}  파라미터 {param}={payload}",
        dynamic={"status": "confirmed", "evidence": ev})
