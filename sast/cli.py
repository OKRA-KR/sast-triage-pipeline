"""SAST+DAST CLI 진입점.

인자 자동판별: 폴더=소스(SAST) · http(s)=URL(DAST recon) · 파일=캡처(패시브). 여러 개 동시 가능.
  python3 -m sast scan <폴더|URL|캡처> ... --out <dir> [--active] [--online]
흐름: 1계층(오프라인 룰+트리아지, 패킷0) → (있으면) 상관분석 → 2·3계층(LLM, --online+설정 시만).
안전: 능동 DAST(패킷 전송)는 --active/--okra 로만(인가 대상 전용). 기본은 오프라인/비파괴.
"""
import argparse, os, re, sys
from .engines import run_all
from . import triage, crossval, playbook, layer2, layer3, blackbox, active, okra, capture, correlate, replay, login, report, env


def _classify(a):
    """positional 인자 + 명시 플래그를 폴더(repo)/URL(verify)/캡처파일로 자동 분류."""
    repo = None
    verify = a.verify or os.environ.get("SAST_VERIFY_URL")
    cap = a.capture or os.environ.get("SAST_CAPTURE")
    for t in (a.targets or []):
        if re.match(r"https?://", t, re.I):
            verify = verify or t
        elif os.path.isdir(t):
            repo = repo or os.path.abspath(t)
        elif os.path.isfile(t):
            cap = cap or os.path.abspath(t)          # 파일 = 캡처(파서가 형식 검증)
        else:
            repo = repo or os.path.abspath(t)        # 미존재 경로 → repo 로 시도(래퍼가 clone 후 dir 전달)
    return repo, verify, cap


def _run_active(exs, findings, require_session, oob=None):
    """능동 role 엔진(캡처/URL 공용). require_session(--full)=인증 세션 확보 실패 시 None(종료).
    아니면(--active) 세션이 있으면 인증 상태로, 없으면 '접근되는 대로' 비인증으로 테스트한다."""
    if require_session:
        ok, sess_a, sess_b = login.working_session(exs)
        if not ok:
            return None
    else:
        sess_a, sess_b = login.build_sessions(exs)     # 자격증명 있으면 로그인, 없으면 (None,None)
        if not sess_a and (os.environ.get("SAST_LOGIN_USER") and os.environ.get("SAST_LOGIN_PASS")):
            print("[!] 로그인 실패 — 접근 가능한 범위만 비인증으로 테스트합니다(SAST_HTTP_COOKIE 있으면 그걸 사용).")
    findings = findings + replay.scan_capture(exs, sess_a, sess_b, oob=oob)   # 무인증 스윕+SQLi/XSS/LFI/IDOR(+OOB)
    buser = os.environ.get("SAST_BRUTE_USER")
    if buser:
        wl = os.environ.get("SAST_BRUTE_WORDLIST")
        words = ([w.strip() for w in open(wl, encoding="utf-8", errors="ignore") if w.strip()]
                 if wl and os.path.isfile(wl) else None)
        findings = findings + login.brute_force(exs, buser, words)
    return findings


def _name_of(repo, verify, cap):
    if repo:
        return os.path.basename(repo.rstrip("/\\"))
    if verify:
        return verify.split("//")[-1].split("/")[0]
    if cap:
        return os.path.splitext(os.path.basename(cap))[0]
    return "scan"


def cmd_scan(a):
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    if a.online:
        os.environ["SAST_ONLINE"] = "1"
    if getattr(a, "insecure", False):
        os.environ["SAST_INSECURE_TLS"] = "1"
        print("[!] TLS 인증서 검증 비활성(--insecure) — MITM/위조응답 위험, 인가 폐쇄망 전용")
    if a.cookie:
        os.environ["SAST_HTTP_COOKIE"] = a.cookie
    if a.header:
        os.environ["SAST_HTTP_HEADERS"] = ";;".join(a.header)

    target, verify_url, cap = _classify(a)          # 인자 자동판별(폴더/URL/캡처)
    have_repo = bool(target and os.path.isdir(target))
    name = a.name or _name_of(target, verify_url, cap)
    kinds = [k for k, v in (("소스", have_repo), ("URL", verify_url), ("캡처", cap)) if v]
    if kinds:
        print(f"[*] 입력 인식: {', '.join(kinds)}")

    findings, engines, layers = [], [], []
    full = a.full or os.environ.get("SAST_FULL")
    oob_listener = None
    if a.oob or os.environ.get("SAST_OOB"):
        from . import oob as _oobmod
        oob_listener = _oobmod.OOBListener()
        print("[!] OOB 모드 — blind SSRF/XXE/RCE 확증. 대상이 콜백주소로 역접속 가능해야 함(인가 전용).")

    # ── Track A : SAST (Repo 있음) ──────────────────────────────
    if have_repo:
        print(f"[*] 스캔: {target}   (환경: {env.mode_label()})")
        findings, engines = run_all(target, out)
        if not engines:
            print("[!] 사용 가능한 엔진이 없습니다 (semgrep 설치 필요)"); return 3
        print(f"[*] 엔진: {', '.join(engines)}  원시 {len(findings)}건")
        layers.append("layer1")
    elif not verify_url and not cap:
        print("[!] 스캔할 대상이 없습니다 — 폴더(소스)/URL/캡처파일 중 하나 이상을 주세요"); return 2

    # ── Track C : 패시브 트래픽 분석 (오프라인, 패킷 0) ──────────
    exs = None
    if cap:
        if not os.path.isfile(cap):
            print(f"[!] 캡처 파일 없음: {cap}"); return 2
        print(f"[*] 패시브 분석: {cap}  (오프라인 · 패킷 0 · 환경: {env.mode_label()})")
        try:
            exs = capture.parse(cap)
        except Exception as e:
            print(f"[!] 캡처 파싱 실패: {e}"); return 2
        inv = capture.endpoints(exs)
        capture.write_endpoints_csv(inv, os.path.join(out, "endpoints.csv"))
        print(f"[*] 엔드포인트 {len(inv)}개 식별 → {out}/endpoints.csv")
        findings = findings + capture.passive_scan(exs)
        layers.append("passive")
        if not engines:
            engines = ["passive"]
        # 캡처의 엔드포인트를 겨냥한 능동 점검(패킷 전송 → 인가 전용, 옵트인). --active=접근되는대로 · --full=세션강제
        if a.active or full or os.environ.get("SAST_ACTIVE"):
            base = verify_url or (exs and f"{exs[0]['scheme']}://{exs[0]['host']}") or ""
            if base:
                if not os.environ.get("SAST_HTTP_COOKIE"):
                    ck = capture.cookie_from(exs)
                    if ck:
                        os.environ["SAST_HTTP_COOKIE"] = ck; print("[*] 캡처 세션 쿠키 재사용")
                print(f"[!] 능동 DAST(캡처 replay{' · --full 세션강제' if full else ''}) — 인가된 대상에만!")
                res = _run_active(exs, findings, require_session=bool(full), oob=oob_listener)
                if res is None:
                    print("[!] 인증 계정/세션 확보 실패 → 전체 점검(--full) 종료. "
                          "SAST_LOGIN_USER/PASS 또는 유효한 --cookie 필요."); return 4
                findings = res; layers.append("replay")

    # ── Track B : 블랙박스 (라이브 URL) ─────────────────────────
    if verify_url and not os.environ.get("SAST_NO_VERIFY"):
        findings = blackbox.probe(findings, verify_url)     # 안전한 수동 recon
        layers.append("blackbox")
        # 도메인만 줘도: 크롤로 엔드포인트 식별 → replay role 엔진(접근되는대로 XSS/SQLi/LFI, --full=세션강제)
        if (a.active or full) and not cap and not os.environ.get("SAST_NO_VERIFY"):
            print(f"[!] 능동 DAST(URL 크롤→replay{' · --full 세션강제' if full else ''}) — 인가된 대상에만!")
            exs_url, npg, nfm = active.crawl_exchanges(verify_url)
            capture.write_endpoints_csv(capture.endpoints(exs_url), os.path.join(out, "endpoints.csv"))
            print(f"[*] 엔드포인트 식별: 페이지 {npg} · 폼 {nfm} → {out}/endpoints.csv")
            res = _run_active(exs_url, findings, require_session=bool(full), oob=oob_listener)
            if res is None:
                print("[!] 인증 계정/세션 확보 실패 → 전체 점검(--full) 종료. "
                      "SAST_LOGIN_USER/PASS 또는 유효한 --cookie 필요."); return 4
            findings = res; layers += ["crawl", "replay"]
        if a.okra or os.environ.get("SAST_OKRA") or os.environ.get("SAST_ZAP"):   # OKRA DAST(엔진 ZAP)
            print("[!] OKRA DAST — 인가된 대상에만! spider+active scan + 중요정보 스캔을 수행합니다.")
            findings = okra.scan(verify_url, findings, out_dir=out)
            layers.append("okra-dast")

    # ── 1계층 마무리: 오프라인 트리아지 (외부통신 0 — 폐쇄망서도 자립 완결) ──
    # 입력이 소스/URL/캡처 무엇이든, 모인 모든 발견에 동일하게 적용된다.
    if findings and not (a.no_triage or os.environ.get("SAST_NO_TRIAGE")):
        rules = triage.load_rules()
        triage.apply(findings, rules)               # 억제/심각도(sev_lock 존중)
        crossval.apply(findings, rules)             # taint 엔진 없으면 자동 no-op
        if have_repo and exs:                       # P2: SAST↔캡처 상관(도달확인/확증)
            correlate.apply(findings, exs); layers.append("correlate")
        playbook.enrich(findings)                   # 공격구문/조치 부여(오프라인)
        layers.append("triage")
    elif findings:
        print("[*] 오프라인 트리아지 OFF")

    # ── 2·3계층: LLM 정오탐 판별 + 심화 (개방망·LLM 설정 시만; 폐쇄망이면 자동 skip) ──
    if findings and env.layer2_enabled():
        print(f"[*] 2·3계층(LLM) — {env.mode_label()} · 대상 {len([f for f in findings if not f.get('suppressed')])}건")
        findings = layer2.triage(findings); layers.append("llm-triage")
        findings = layer3.deepen(findings); layers.append("llm-deepen")
    elif findings:
        print("[*] 2·3계층(LLM) OFF — LLM 미설정(SAST_LLM_ENDPOINT/SAST_LLM_KEY). 1계층 결과로 완결.")

    if oob_listener is not None:
        oob_listener.stop()
    src = target if have_repo else (verify_url or cap or "")
    truncated = replay.truncated[0] or active.truncated[0]
    res = report.build(name, src, engines or ["blackbox"], findings, out,
                       mode="+".join(layers) + f" [{env.mode_label()}]", truncated=truncated)
    s = res["summary"]
    if truncated:
        print("[!] 주의: 요청 상한 도달로 능동 프로브가 부분적입니다(meta.truncated=true).")
    print(f"[*] 억제 {s['suppressed']} · 검토대상 {s['needs_review']} · 동적확증 {s['dynamic_confirmed']} · 심각도 {s['by_severity']}")
    print(f"[*] 결과 {out}/results.json  |  대시보드 {out}/index.html")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="sast", description="repo-무관 SAST+DAST (오프라인 우선, 계층형)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="소스/URL/캡처 자동판별 통합 스캔")
    sc.add_argument("targets", nargs="*", default=[],
                    help="대상(여러 개 가능): 폴더=소스 · http(s)=URL · 파일=캡처. 자동 판별.")
    sc.add_argument("--out", required=True, help="결과 출력 폴더")
    sc.add_argument("--name", default=None, help="표시 이름(기본: 폴더명/호스트)")
    sc.add_argument("--online", action="store_true", help="개방망: 2·3계층(LLM) 활성화")
    sc.add_argument("--no-triage", action="store_true", help="1계층 오프라인 트리아지 끄기")
    sc.add_argument("--verify", default=None, metavar="URL", help="블랙박스: 라이브 URL 점검(수동)")
    sc.add_argument("--capture", default=None, metavar="FILE",
                    help="패시브 분석: Burp items XML/HAR 캡처(오프라인, 패킷0) → 엔드포인트 CSV+취약점")
    sc.add_argument("--active", action="store_true", help="경량 능동 DAST(내장, 인가 전용)")
    sc.add_argument("--full", action="store_true",
                    help="원스텝 전체 점검: 인증 세션 확보(못 찾으면 종료)→무인증+SQLi/XSS/IDOR(+브루트) 일괄")
    sc.add_argument("--okra", "--zap", dest="okra", action="store_true",
                    help="OKRA DAST(ZAP 엔진 spider+ascan + 중요정보 스캔, 인가 전용)")
    sc.add_argument("--oob", action="store_true",
                    help="OOB 콜백 리스너(blind SSRF/XXE/RCE 확증, 인가 전용; SAST_OOB_HOST 로 콜백주소 지정)")
    sc.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 끔(자기서명 폐쇄망 대상 전용)")
    sc.add_argument("--cookie", default=None, help="DAST 요청 쿠키(예: 'PHPSESSID=..')")
    sc.add_argument("--header", action="append", default=[], metavar="'N: V'", help="DAST 커스텀 헤더(반복 가능)")
    sc.set_defaults(func=cmd_scan)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
