#!/usr/bin/env python3
"""WebGoat 자동 캡처 하네스 — 인증 브라우징을 자동화해 HAR 생성(→ okra 로 스캔).

SPA(WebGoat)는 레슨이 Angular 라우팅으로 동적 로드돼 크롤이 못 닿는다. 이 하네스는:
  1) 로그인(세션 프라이밍)  2) lessonmenu 로 레슨 열거  3) 각 레슨 HTML(예측 URL)에서
  공격 폼(action+필드) 추출  4) 그 엔드포인트로 정상 요청 전송(트래픽 생성)  5) 전부 HAR 로 기록.
결과 HAR 를 `./okra webgoat.har --1layer` 로 스캔하면 replay 가 레슨 파라미터에 payload 주입.

stdlib only. 인가된 로컬 훈련 타깃 전용.
사용: python3 bench/tools/webgoat_capture.py [base] [user] [pass] [out.har]
"""
import json, re, sys, urllib.request, urllib.error
from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/WebGoat"
USER = sys.argv[2] if len(sys.argv) > 2 else "okratester"
PW = sys.argv[3] if len(sys.argv) > 3 else "Okra12345"
OUT = sys.argv[4] if len(sys.argv) > 4 else "webgoat.har"
ENTRIES = []
COOKIE = [""]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)   # 리다이렉트 비추적 → 302 의 Set-Cookie 포착


def _req(method, url, data=None, ctype=None):
    body = urlencode(data).encode() if data else None
    h = {}
    if COOKIE[0]:
        h["Cookie"] = COOKIE[0]
    if ctype:
        h["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        r = _OPENER.open(req, timeout=10)
        status, rh, rb = r.status, dict(r.headers.items()), r.read(200000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, rh, rb = e.code, dict((e.headers or {}).items()), (e.read(50000).decode("utf-8", "replace") if hasattr(e, "read") else "")
    except Exception as ex:
        return None
    sc = rh.get("Set-Cookie", "")
    if sc:
        COOKIE[0] = sc.split(";", 1)[0]
    # HAR 엔트리 기록
    ENTRIES.append({
        "request": {"method": method, "url": url,
                    "headers": [{"name": k, "value": v} for k, v in h.items()],
                    "postData": {"text": urlencode(data)} if data else {"text": ""}},
        "response": {"status": status,
                     "headers": [{"name": k, "value": v} for k, v in rh.items()],
                     "content": {"mimeType": rh.get("Content-Type", ""), "text": rb}}})
    return status, rh, rb


class _Forms(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms = []; self._f = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._f = {"action": a.get("action", ""), "method": (a.get("method") or "post").lower(), "fields": []}
        elif tag in ("input", "textarea", "select") and self._f is not None and a.get("name"):
            self._f["fields"].append(a["name"])
    def handle_endtag(self, tag):
        if tag == "form" and self._f is not None:
            self.forms.append(self._f); self._f = None


def login():
    _req("GET", BASE + "/login")                                   # 세션 프라이밍
    s = _req("POST", BASE + "/login", {"username": USER, "password": PW},
             "application/x-www-form-urlencoded")
    print(f"[*] 로그인: status {s[0] if s else '실패'} · 세션 {COOKIE[0][:24]}")
    return s and s[0] in (200, 302)


def lessons():
    r = _req("GET", BASE + "/service/lessonmenu.mvc")
    names = sorted(set(re.findall(r"#lesson/([A-Za-z0-9_]+)\.lesson", r[2]))) if r else []
    print(f"[*] 레슨 {len(names)}개 발견")
    return names


# 폼 외에 Angular 가 동적 호출하는 알려진 데이터 엔드포인트(파라미터 주입 지점)
KNOWN_GET = [
    "/SqlInjectionMitigations/servers?column=name",
    "/SqlInjectionAdvanced/challenge_Login?username_login=a&password_login=b",
    "/IDOR/profile/2342384",
    "/access-control/user-hash",
]


def exercise():
    for path in KNOWN_GET:                              # 알려진 GET 데이터 엔드포인트
        _req("GET", BASE + path)
    n_forms = 0
    for name in lessons():
        r = _req("GET", f"{BASE}/{name}.lesson.lesson")             # 레슨 HTML(폼 포함)
        if not r or r[0] != 200:
            continue
        p = _Forms()
        try:
            p.feed(r[2])
        except Exception:
            pass
        for f in p.forms:
            action = urljoin(BASE + "/", f["action"])
            if "attack" not in action.lower():
                continue
            data = {fld: "1" for fld in f["fields"] if fld}
            if not data:
                continue
            _req("POST", action, data, "application/x-www-form-urlencoded")   # 공격 엔드포인트 정상요청
            n_forms += 1
    print(f"[*] 공격 폼 {n_forms}개 실행 → 트래픽 생성")


if __name__ == "__main__":
    if not login():
        print("[!] 로그인 실패 — 계정/비번 확인(6~10자)"); sys.exit(1)
    exercise()
    json.dump({"log": {"version": "1.2", "creator": {"name": "okra-webgoat-capture"}, "entries": ENTRIES}},
              open(OUT, "w", encoding="utf-8"), ensure_ascii=False)
    print(f"[*] HAR 저장: {OUT} · 요청 {len(ENTRIES)}건")
    print(f"    스캔: ./okra {OUT} --1layer")
