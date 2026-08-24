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


def _ctx():
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    return c


def _fetch(url, redirect=True):
    if _req_count[0] >= MAX_REQ:
        return None
    _req_count[0] += 1
    time.sleep(DELAY)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    op = urllib.request.build_opener() if redirect else urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with op.open(req, timeout=TIMEOUT) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, (e.read(50000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception:
        return None


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self.forms = []; self._f = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._f = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "fields": []}
        elif tag in ("input", "textarea", "select") and self._f is not None and a.get("name"):
            self._f["fields"].append(a["name"])
    def handle_endtag(self, tag):
        if tag == "form" and self._f is not None:
            self.forms.append(self._f); self._f = None


def _crawl(base):
    host = urlparse(base).netloc
    seen, queue, pages, forms = set(), [base], [], []
    while queue and len(seen) < MAX_PAGES:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = _fetch(url)
        if not r or not r[2]:
            continue
        pages.append(url)
        p = _Links()
        try:
            p.feed(r[2])
        except Exception:
            pass
        for f in p.forms:
            f["page"] = url; forms.append(f)
        for href in p.links:
            u = urljoin(url, href)
            if urlparse(u).netloc == host and u not in seen and u.split("#")[0] not in seen:
                queue.append(u.split("#")[0])
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
    """fetch_with(payload)->resp ; baseline 은 payload='' 로."""
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
    return out


def scan(base_url):
    base = base_url.rstrip("/")
    print(f"[*] 능동 DAST: {base} (인가 대상 전제 · 비파괴 payload)")
    pages, forms = _crawl(base)
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

    # 2) 폼 필드 (GET/POST)
    for f in forms:
        action = urljoin(f["page"], f["action"] or f["page"])
        for key in f["fields"]:
            def fw(pay, redirect=True, a=action, fields=f["fields"], k=key):
                data = {fld: (pay if fld == k else "test") for fld in fields}
                return _fetch(a + ("?" + urlencode(data)), redirect=redirect)  # GET 폼 위주(안전)
            for cat, sev, payload, ev in _probe_point(fw):
                findings.append(_finding(cat, sev, action, key, payload, ev, form=True))

    print(f"[*] 능동 DAST: 요청 {_req_count[0]}건 · 페이지 {len(pages)} · 폼 {len(forms)} · 확증 {len(findings)}건")
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
