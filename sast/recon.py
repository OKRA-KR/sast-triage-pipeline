"""공격표면 정찰 — 하위도메인 열거 + 라이브 호스트 프로빙 (OKRA 원스텝 통합용, stdlib).

standalone recon 도구와 동일 로직을 sast 패키지에 내장한다. --recon 옵션이 켜지면
주어진 URL 의 등록가능 도메인(registrable) 아래 하위도메인을 훑어 살아있는 호스트를
찾아내고, OKRA 가 그 각각을 크롤→능동 DAST 로 이어서 점검한다. payload 주입은 없다(순수 발견).
"""
import concurrent.futures as cf, json, socket
import urllib.request, urllib.error
from urllib.parse import urlparse
from . import env

UA = "okra-recon/1.0"

# 내장 하위도메인 사전(자주 쓰이는 것) — --recon-wordlist 로 확장
SUBS = ("www api api2 apis dev develop development staging stage stg test testing qa uat "
        "admin administrator portal dashboard console manage mgmt app apps web webapp "
        "mail smtp imap pop webmail email mx mx1 mx2 ns ns1 ns2 dns vpn remote gateway "
        "git gitlab svn jenkins ci cd build docker registry k8s kube grafana kibana "
        "prometheus status health monitor monitoring log logs elk splunk "
        "db database mysql postgres redis mongo sql backup bak old legacy archive "
        "static assets cdn img images media files upload uploads download downloads "
        "shop store cart pay payment billing account accounts auth login sso oauth id "
        "blog news forum community help support docs doc wiki kb faq "
        "internal intranet corp private secure beta alpha demo sandbox preview "
        "m mobile api-dev api-test api-staging v1 v2 v3 gw proxy lb "
        "caps mycaps mmycaps capsdev caps-dev").split()

# .kr 등 2단계 TLD — 등록가능 도메인 판정용
_KR_2LD = {"co", "or", "ne", "go", "ac", "re", "pe", "hs", "ms", "es", "sc", "kg"}


def registrable(host):
    """mmycapsdev.skshieldus.com -> skshieldus.com,  x.example.co.kr -> example.co.kr."""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if parts[-1] == "kr" and parts[-2] in _KR_2LD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _resolve(host):
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def _crtsh(domain):
    out = set()
    try:
        with urllib.request.urlopen(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20) as r:
            for row in json.loads(r.read().decode("utf-8", "replace")):
                for nm in (row.get("name_value", "") or "").splitlines():
                    nm = nm.strip().lstrip("*.").lower()
                    if nm.endswith("." + domain) or nm == domain:
                        out.add(nm)
        print(f"[*] recon: crt.sh(패시브) {len(out)}개 후보")
    except Exception as e:
        print(f"[!] recon: crt.sh 조회 실패 — {str(e)[:80]}")
    return out


def enumerate_subs(domain, wordlist=None, passive=False, threads=40):
    """domain 아래 하위도메인 후보를 DNS 해석해 살아있는 것만 {host: [ip..]} 로 반환."""
    cands = {domain} | {f"{s}.{domain}" for s in SUBS}
    if wordlist:
        try:
            cands |= {f"{l.strip()}.{domain}" for l in open(wordlist, encoding="utf-8", errors="ignore") if l.strip()}
        except OSError as e:
            print(f"[!] recon: 워드리스트 읽기 실패 — {e}")
    if passive:
        cands |= _crtsh(domain)
    found = {}
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for host, ips in zip(cands, ex.map(_resolve, cands)):
            if ips:
                found[host] = ips
    return dict(sorted(found.items()))


def probe(netloc, schemes=("https", "http"), timeout=6):
    """netloc(host 또는 host:port) 프로빙 → 첫 응답 스킴의 메타 dict, 없으면 None."""
    for scheme in schemes:
        try:
            req = urllib.request.Request(f"{scheme}://{netloc}/", headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=env.ssl_context()) as r:
                body = r.read(4000).decode("utf-8", "replace")
                hdr = {k.lower(): v for k, v in r.headers.items()}
                status = r.status
        except urllib.error.HTTPError as e:
            hdr = {k.lower(): v for k, v in (e.headers or {}).items()}
            status = e.code; body = ""
        except Exception:
            continue
        import re
        m = re.search(r"<title[^>]*>([^<]{1,120})", body, re.I)
        return dict(host=netloc, scheme=scheme, status=status,
                    title=(m.group(1).strip()[:80] if m else ""),
                    server=hdr.get("server", ""), base=f"{scheme}://{netloc}")
    return None


def discover(target_url, wordlist=None, passive=False, threads=40, same_port=False):
    """target_url 로부터 등록가능 도메인 하위 라이브 호스트를 찾아 base URL 목록을 만든다.
    반환: (subs {host:[ip]}, live [dict..]) — live[i]['base'] 가 scheme://host[:port]."""
    p = urlparse(target_url)
    host = (p.hostname or "").lower()
    port = f":{p.port}" if (same_port and p.port) else ""
    reg = registrable(host)
    print(f"[*] recon: '{reg}' 하위도메인 열거 (기준 호스트 {host})")
    subs = enumerate_subs(reg, wordlist, passive, threads)
    print(f"[*] recon: 하위도메인 해석 {len(subs)}개 → 라이브 프로빙")
    live = []
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for res in ex.map(lambda h: probe(h + port), subs.keys()):
            if res:
                live.append(res)
    live.sort(key=lambda x: x["host"])
    print(f"[*] recon: 라이브 호스트 {len(live)}개")
    return subs, live


def write_reports(subs, live, out_dir):
    import os
    try:
        with open(os.path.join(out_dir, "subdomains.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(subs.keys()))
        with open(os.path.join(out_dir, "live.csv"), "w", encoding="utf-8-sig", newline="") as f:
            f.write("host,scheme,status,title,server\n")
            for h in live:
                f.write(f"{h['host']},{h['scheme']},{h['status']},\"{h['title']}\",\"{h['server']}\"\n")
    except OSError as e:
        print(f"[!] recon: 결과 파일 쓰기 실패 — {e}")
