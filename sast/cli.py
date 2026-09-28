"""SAST+DAST CLI 진입점.

입력(축①): 폴더=소스(SAST) · http(s)=URL(DAST) · 파일=캡처(패시브). positional 로 자동판별, 여러 개 동시 가능.
  python3 -m sast scan <폴더|URL|캡처> ... --out <dir> [--active | --full | --domain]
점검 깊이(축②) — 세 모드:
  (없음)   안전 패시브: 능동 프로브 0·LLM 0 (기본, 비파괴)
  --active 능동 DAST + 오프라인 트리아지 + recon(하위도메인 정찰). LLM OFF, 폐쇄망 자립
  --full   --active + LLM 2·3계층 심화 (LLM 설정 시)
  --domain --active 를 이 도메인 하나만(recon OFF). 단일 호스트 점검
흐름: 1계층(오프라인 룰+트리아지, 패킷0) → (있으면) 상관분석 → 2·3계층(LLM, --full+설정 시만).
안전: 능동 DAST(패킷 전송)는 --active/--full/--domain 로만(인가 대상 전용).
"""
import argparse, os, re, sys
from .engines import run_all
from . import triage, crossval, playbook, layer2, layer3, blackbox, active, okra, capture, correlate, replay, login, report, env, recon
from .core import Config, ScanContext, resolve_name


def _classify(a):
    """positional 인자를 폴더(repo)/URL(verify)/캡처파일로 자동 분류.
    명시 플래그는 제거(축① 정리) — 하위호환용 env(SAST_VERIFY_URL/SAST_CAPTURE)만 남긴다."""
    repo = None
    verify = getattr(a, "verify", None) or os.environ.get("SAST_VERIFY_URL")
    cap = getattr(a, "capture", None) or os.environ.get("SAST_CAPTURE")
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


def _run_active(exs, findings, require_session, oob=None, presession=None):
    """능동 role 엔진(캡처/URL 공용). require_session(--full)=인증 세션 확보 실패 시 None(종료).
    아니면(--active) 세션이 있으면 인증 상태로, 없으면 '접근되는 대로' 비인증으로 테스트한다.
    presession=(a,b) 가 주어지면 재로그인 없이 그 세션을 사용(URL 인증 재크롤 후)."""
    if presession is not None:
        sess_a, sess_b = presession
    elif require_session:
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


# 표시 이름 결정은 core.context 로 이관 — 여기선 하위호환 재노출(테스트/외부 참조용).
# 모드 해석(_apply_mode)은 core.Config.apply_mode 로 이관됨.
_name_of = resolve_name


def cmd_scan(a):
    cfg = Config.from_args(a)
    out = os.path.abspath(cfg.out)
    os.makedirs(out, exist_ok=True)
    cfg.apply_transport()                            # TLS/쿠키/헤더 → 다운스트림 env 브리지

    target, verify_url, cap = _classify(a)           # 인자 자동판별(폴더/URL/캡처)
    ctx = ScanContext(config=cfg, repo=target, verify_url=verify_url, capture=cap)
    have_repo = ctx.have_repo
    name = ctx.name
    kinds = [k for k, v in (("소스", have_repo), ("URL", verify_url), ("캡처", cap)) if v]
    if kinds:
        print(f"[*] 입력 인식: {', '.join(kinds)}")

    run_active = cfg.apply_mode()                    # 축② 깊이 해석(모드 배너 + LLM/recon 게이트 env)
    # 절차 상태는 아직 지역변수(스트랭글러: 스테이지로 순차 이사하며 ctx 로 흡수) ──
    findings, engines, layers = [], [], []
    endpoints_all, recon_live, recon_subs = [], [], {}   # 결과 워크북(Endpoints·Recon 시트)용 수집
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
        if capture.is_burp_issues(cap):        # Burp Scanner 이슈 export → finding 병합
            print(f"[*] Burp 스캐너 이슈 파싱: {cap}  (오프라인 · 스캐너 확정=동적확증)")
            try:
                bfindings, exs = capture.parse_burp_issues(cap)
            except Exception as e:
                print(f"[!] Burp 이슈 파싱 실패: {e}"); return 2
            findings = findings + bfindings
            conf = sum(1 for f in bfindings if (f.get("dynamic") or {}).get("status") == "confirmed")
            print(f"[*] Burp 이슈 {len(bfindings)}건 병합(동적확증 {conf} · Tentative→검토대상)")
            engines = engines or ["burp"]
            layers.append("burp-issues")
        else:
            print(f"[*] 패시브 분석: {cap}  (오프라인 · 패킷 0 · 환경: {env.mode_label()})")
            try:
                exs = capture.parse(cap)
            except Exception as e:
                print(f"[!] 캡처 파싱 실패: {e}"); return 2
            findings = findings + capture.passive_scan(exs)
            engines = engines or ["passive"]
            layers.append("passive")
        endpoints_all += capture.endpoints(exs)     # 엔드포인트 인벤토리(공통) → 결과 워크북으로
        if capture.is_burp_issues(cap):            # Burp 응답에도 OKRA 고유 secrets/PII 적용
            findings = findings + capture.passive_scan(exs)
        # 캡처의 엔드포인트를 겨냥한 능동 점검(패킷 전송 → 인가 전용, 옵트인). 세션은 best-effort(접근되는대로)
        if run_active:
            base = verify_url or (exs and f"{exs[0]['scheme']}://{exs[0]['host']}") or ""
            if base:
                if not os.environ.get("SAST_HTTP_COOKIE"):
                    ck = capture.cookie_from(exs)
                    if ck:
                        os.environ["SAST_HTTP_COOKIE"] = ck; print("[*] 캡처 세션 쿠키 재사용")
                print("[!] 능동 DAST(캡처 replay) — 인가된 대상에만!")
                findings = _run_active(exs, findings, require_session=False, oob=oob_listener)
                layers.append("replay")

    # ── Track B : 블랙박스 (라이브 URL, --recon 시 하위도메인으로 확장) ──
    if verify_url and not os.environ.get("SAST_NO_VERIFY"):
        verify_urls = [verify_url]
        # recon(OSINT): --active/--full 이면 기본 ON — 하위도메인 열거→라이브 호스트를 점검대상에 합류(원스텝).
        #   끄기: --no-recon(또는 SAST_NO_RECON). 패시브 소스(crt.sh/Wayback)는 도메인이 제3자로 나가므로 --recon-passive 로만.
        do_recon = (not getattr(a, "no_recon", False) and not os.environ.get("SAST_NO_RECON")
                    and (getattr(a, "recon", False) or run_active or os.environ.get("SAST_RECON")))
        if do_recon:
            subs, live = recon.discover(
                verify_url, wordlist=getattr(a, "recon_wordlist", None),
                passive=getattr(a, "recon_passive", False),
                threads=int(os.environ.get("SAST_RECON_THREADS", "40")),
                same_port=getattr(a, "recon_same_port", False))
            recon_subs, recon_live = subs, live         # 결과 워크북 Recon 시트로
            recon.write_reports(subs, live, out)
            for h in live:
                if h["base"] not in verify_urls:
                    verify_urls.append(h["base"])
            print(f"[*] recon: 점검 대상 {len(verify_urls)}개(원본+라이브 하위도메인 {len(live)}) · 정찰 해석 {len(subs)}개")
            layers.append("recon")
            # 패시브(옵트인): Wayback 과거 URL → urls.txt + 엔드포인트 인벤토리(결과 워크북에 합류)
            if getattr(a, "recon_passive", False):
                _reg, wb = recon.passive_urls(verify_url)
                if wb:
                    try:
                        with open(os.path.join(out, "urls.txt"), "w", encoding="utf-8") as f:
                            f.write("\n".join(sorted(wb)))
                    except OSError as e:
                        print(f"[!] recon: urls.txt 기록 실패 — {e}")
                    endpoints_all += recon.wayback_endpoints(wb)
                    print(f"[*] recon: Wayback URL {len(wb)}개 → urls.txt (엔드포인트 인벤토리에 합류)")

        base_cookie = os.environ.get("SAST_HTTP_COOKIE")   # 호스트 간 세션 누수 방지용 스냅샷
        for vu in verify_urls:
            if base_cookie is not None:
                os.environ["SAST_HTTP_COOKIE"] = base_cookie
            else:
                os.environ.pop("SAST_HTTP_COOKIE", None)
            if len(verify_urls) > 1:
                print(f"[*] URL 점검: {vu}")
            findings = blackbox.probe(findings, vu)     # 안전한 수동 recon
            if "blackbox" not in layers:
                layers.append("blackbox")
            # 도메인만 줘도: 크롤 → (로그인 되면 인증 재크롤: 레슨/JS API 도달) → replay role 엔진
            if run_active and not cap:
                print("[!] 능동 DAST(URL 크롤→replay) — 인가된 대상에만!")
                exs_url, npg, nfm, bleaks = active.crawl_exchanges(vu)  # 1차: 로그인 폼 발견용(+본문 누수)
                sess_a, sess_b = login.build_sessions(exs_url)         # 자격증명/캡처추출로 로그인
                if sess_a and sess_a.cookie and not str(sess_a.cookie).startswith("Bearer "):
                    os.environ["SAST_HTTP_COOKIE"] = sess_a.cookie
                    print("[*] 로그인 세션으로 인증 재크롤 — 로그인 뒤 페이지·JS API 도달")
                    # 로그인 랜딩을 시드로 — 비인증 base 가 인증 시 404/다른 진입점인 앱(Spring 등) 대응
                    seeds = [sess_a.landing] if getattr(sess_a, "landing", None) else None
                    if seeds:
                        print(f"[*] 인증 진입점 시드: {seeds[0]}")
                    aexs, anpg, anfm, ableaks = active.crawl_exchanges(vu, seeds=seeds)   # 2차: 인증 상태 재크롤
                    if len(aexs) >= len(exs_url):                      # 인증 크롤이 더 찾았을 때만 채택
                        exs_url, npg, nfm, bleaks = aexs, anpg, anfm, ableaks
                    else:
                        print(f"[*] 인증 재크롤 {len(aexs)}건 ≤ 비인증 {len(exs_url)}건 — 비인증 결과 유지")
                endpoints_all += capture.endpoints(exs_url)
                findings = findings + bleaks                           # A: 로드 본문서 식별한 취약정보 합류
                # SAST→DAST 라우트 다리: 소스 라우트(@GetMapping·route 등)를 DAST 프로브 대상으로.
                # SPA/AJAX 앱은 공격 엔드포인트가 정적 크롤로 안 잡혀 → 소스에서 결정론적으로 발굴.
                if have_repo:
                    from . import routes as routes_mod
                    troutes = routes_mod.extract_routes(target)
                    if troutes:
                        # 인벤토리(표면 목록)는 전체 — 발굴은 다 한다.
                        endpoints_all += capture.endpoints(
                            routes_mod.to_exchanges(troutes, vu))
                        # 능동 주입은 안전레일로 게이트: GET 기본, 쓰기 옵트인, 파괴적 제외.
                        allow_writes = bool(getattr(a, "probe_writes", False)
                                            or os.environ.get("SAST_PROBE_WRITES"))
                        allow_destr = bool(os.environ.get("SAST_PROBE_DESTRUCTIVE"))
                        probe = routes_mod.select_for_active(troutes, allow_writes, allow_destr)
                        rex = routes_mod.to_exchanges(probe, vu, cookie=os.environ.get("SAST_HTTP_COOKIE"))
                        exs_url = exs_url + rex
                        writes = sum(1 for r in troutes if r.get("write") and not r.get("destructive"))
                        destr = sum(1 for r in troutes if r.get("destructive"))
                        print(f"[*] SAST→DAST 라우트 다리: 발굴 {len(troutes)}개(인벤토리) · "
                              f"능동 프로브 {len(probe)}개 "
                              f"[쓰기 {writes}건 {'포함' if allow_writes else '보류(--probe-writes)'} · "
                              f"파괴적 {destr}건 {'포함' if allow_destr else '제외'}]")
                        if "route-bridge" not in layers:
                            layers.append("route-bridge")
                findings = _run_active(exs_url, findings, require_session=False,
                                       oob=oob_listener, presession=(sess_a, sess_b))
                for _l in ("crawl", "replay"):
                    if _l not in layers:
                        layers.append(_l)
            if os.environ.get("SAST_OKRA") or os.environ.get("SAST_ZAP"):   # OKRA DAST(엔진 ZAP) — 옵트인 env
                print("[!] OKRA DAST — 인가된 대상에만! spider+active scan + 중요정보 스캔을 수행합니다.")
                findings = okra.scan(vu, findings, out_dir=out)
                if "okra-dast" not in layers:
                    layers.append("okra-dast")
        if base_cookie is not None:
            os.environ["SAST_HTTP_COOKIE"] = base_cookie
        else:
            os.environ.pop("SAST_HTTP_COOKIE", None)

    # ── 1계층 마무리: 오프라인 트리아지 (외부통신 0 — 폐쇄망서도 자립 완결) ──
    # 입력이 소스/URL/캡처 무엇이든, 모인 모든 발견에 동일하게 적용된다.
    if findings and not os.environ.get("SAST_NO_TRIAGE"):
        rules = triage.load_rules()
        triage.apply(findings, rules)               # 억제/심각도(sev_lock 존중)
        crossval.apply(findings, rules)             # taint 엔진 없으면 자동 no-op
        if have_repo and exs:                       # P2: SAST↔캡처 상관(도달확인/확증)
            correlate.apply(findings, exs); layers.append("correlate")
        playbook.enrich(findings)                   # 공격구문/조치 부여(오프라인)
        # ── 5단계: 성립검증(오프라인 결정론 우선; LLM 있으면 코드조건만 보강) ──
        findings = layer2.triage(findings, exs=exs, root=(target if have_repo else None)); layers.append("exploit-check")
        layers.append("triage")
    elif findings:
        print("[*] 오프라인 트리아지 OFF")

    # ── 3계층: LLM 심화(확증건 PoC/조치 생성) — 개방망·LLM 설정 시만 ──
    if findings and env.layer2_enabled():
        print(f"[*] 3계층(LLM 심화) — {env.mode_label()}")
        findings = layer3.deepen(findings); layers.append("llm-deepen")
    elif findings:
        print("[*] 3계층(LLM 심화) OFF — LLM 미설정. 2계층 성립검증 결과로 완결.")

    if oob_listener is not None:
        oob_listener.stop()

    # ── 결과 인벤토리 워크북: <name>_result.xlsx (Endpoints + Recon + Exposure 3시트, 파일명에 도메인) ──
    if endpoints_all or recon_live or findings:
        if run_active and verify_url:               # 능동 모드: 상태코드 보강 + 404 완전불가 제외
            endpoints_all = active.enrich_status(endpoints_all)
        _EXPO = {"hardcoded-secret", "sensitive-data", "info-disclosure"}   # 로드 본문 누수(A)
        exposure = [f for f in findings if f.get("category") in _EXPO and not f.get("suppressed")]
        wb = report.write_result_workbook(name, out, endpoints_all, recon_live, recon_subs, exposure=exposure)
        if wb:
            print(f"[*] 결과 워크북 → {os.path.basename(wb['path'])}  "
                  f"(Endpoints {wb['endpoints']} · Recon {wb['recon']} · Exposure {wb['exposure']})")

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
    # ── 축② 점검 깊이 — 세 모드(상호배타). 없으면 안전 패시브. 능동 DAST 는 인가 대상 전용. ──
    depth = sc.add_mutually_exclusive_group()
    depth.add_argument("--active", action="store_true",
                       help="능동 DAST + 오프라인 트리아지 + recon(하위도메인 정찰). LLM OFF, 폐쇄망 자립")
    depth.add_argument("--full", action="store_true",
                       help="--active + LLM 2·3계층 심화(LLM 설정 시)")
    depth.add_argument("--domain", action="store_true",
                       help="--active 를 이 도메인 하나만(recon OFF). 단일 호스트 점검")
    sc.add_argument("--recon", action="store_true",
                    help="정찰 강제 ON(패시브 스캔에서도). --active/--full 은 기본 ON — 하위도메인 열거→라이브 호스트를 점검대상에 합류")
    sc.add_argument("--no-recon", dest="no_recon", action="store_true",
                    help="정찰 OFF: --active/--full 의 기본 recon(하위도메인 열거) 비활성(단일 호스트만)")
    sc.add_argument("--recon-passive", action="store_true",
                    help="패시브 소스까지: crt.sh(CT)+Wayback 과거URL+DoH 리졸버 — 타깃 무접촉이나 도메인명이 제3자로 나감(기본 OFF)")
    sc.add_argument("--recon-wordlist", default=None, metavar="FILE",
                    help="recon 하위도메인 사전 파일(줄당 1개, 내장 사전에 추가)")
    sc.add_argument("--recon-same-port", action="store_true",
                    help="recon 으로 찾은 하위도메인을 대상과 같은 포트로 프로빙(기본: 443/80)")
    sc.add_argument("--probe-writes", dest="probe_writes", action="store_true",
                    help="라우트 다리에서 상태변경(POST/PUT/PATCH) 엔드포인트도 능동 주입(기본: GET만, 인가 대상 전용). "
                         "파괴적(삭제·결제·초기화 등)은 이 옵션으로도 제외 — SAST_PROBE_DESTRUCTIVE=1 로만 강제")
    sc.add_argument("--oob", action="store_true",
                    help="OOB 콜백 리스너(blind SSRF/XXE/RCE 확증, 인가 전용; SAST_OOB_HOST 로 콜백주소 지정)")
    sc.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 끔(자기서명 폐쇄망 대상 전용)")
    sc.add_argument("--cookie", default=None, help="DAST 요청 쿠키(예: 'PHPSESSID=..')")
    sc.add_argument("-H", "--header", action="append", default=[], metavar="'N: V'",
                    help="DAST 커스텀 헤더(반복 가능): -H 'Authorization: Bearer ..' -H 'X-Api-Key: ..'")
    sc.set_defaults(func=cmd_scan)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
