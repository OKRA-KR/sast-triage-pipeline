"""SAST+DAST CLI 진입점.

Track A (Repo 있음)  → SAST:  1계층(오프라인 룰+트리아지) → 2계층(LLM 트리아지) → 3계층(LLM 심화)
Track B (Repo 없음)  → 블랙박스: 라이브 URL 엔드포인트 식별 → 공격 가능 포인트

환경 게이팅: 기본 폐쇄망(offline) → 2·3계층 OFF. `--online`(SAST_ONLINE) + LLM 설정 시만 ON.
  python3 -m sast scan <target> --out <dir> [--online] [--verify <URL>] [--no-triage]
"""
import argparse, os, sys
from .engines import run_all
from . import triage, crossval, playbook, layer2, layer3, blackbox, active, okra, capture, correlate, replay, report, env


def cmd_scan(a):
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    verify_url = a.verify or os.environ.get("SAST_VERIFY_URL")
    if a.online:
        os.environ["SAST_ONLINE"] = "1"
    if a.cookie:
        os.environ["SAST_HTTP_COOKIE"] = a.cookie
    if a.header:
        os.environ["SAST_HTTP_HEADERS"] = ";;".join(a.header)

    target = os.path.abspath(a.target) if a.target else None
    have_repo = bool(target and os.path.isdir(target))
    name = a.name or (os.path.basename(target.rstrip("/\\")) if have_repo
                      else (verify_url.split("//")[-1].split("/")[0] if verify_url
                            else (os.path.splitext(os.path.basename(a.capture))[0] if a.capture else "scan")))

    findings, engines, layers = [], [], []

    # ── Track A : SAST (Repo 있음) ──────────────────────────────
    if have_repo:
        print(f"[*] 스캔: {target}   (환경: {env.mode_label()})")
        findings, engines = run_all(target, out)
        if not engines:
            print("[!] 사용 가능한 엔진이 없습니다 (semgrep 설치 필요)"); return 3
        print(f"[*] 엔진: {', '.join(engines)}  원시 {len(findings)}건")
        layers.append("layer1")
    elif not verify_url and not (a.capture or os.environ.get("SAST_CAPTURE")):
        print(f"[!] 대상 경로가 없고 --verify/--capture 도 없습니다: {a.target}"); return 2

    # ── Track C : 패시브 트래픽 분석 (오프라인, 패킷 0) ──────────
    cap = a.capture or os.environ.get("SAST_CAPTURE")
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
        # 캡처의 엔드포인트를 그대로 겨냥한 정밀 능동 점검(패킷 전송 → 인가 전용, 옵트인)
        if a.active or os.environ.get("SAST_ACTIVE"):
            base = verify_url or (exs and f"{exs[0]['scheme']}://{exs[0]['host']}") or ""
            if base:
                if not os.environ.get("SAST_HTTP_COOKIE"):
                    ck = capture.cookie_from(exs)
                    if ck:
                        os.environ["SAST_HTTP_COOKIE"] = ck; print("[*] 캡처 세션 쿠키 재사용")
                print("[!] 능동 DAST(캡처 replay) — 인가된 대상에만! 실제 요청을 재전송하며 표적 검증합니다.")
                findings = findings + replay.scan_capture(exs)     # 실제 인증 요청 재전송(SQLi/XSS/IDOR)
                layers.append("replay")

    # ── Track B : 블랙박스 (라이브 URL) ─────────────────────────
    if verify_url and not os.environ.get("SAST_NO_VERIFY"):
        findings = blackbox.probe(findings, verify_url)     # 안전한 수동 recon
        layers.append("blackbox")
        if a.active or os.environ.get("SAST_ACTIVE"):       # 경량 능동 DAST (내장, 의존성 0)
            print("[!] 능동 DAST 모드 — 인가된 대상에만! 실제 탐지 payload 를 전송합니다.")
            findings = findings + active.scan(verify_url)
            layers.append("active-dast")
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

    src = target if have_repo else (verify_url or cap or "")
    res = report.build(name, src, engines or ["blackbox"], findings, out,
                       mode="+".join(layers) + f" [{env.mode_label()}]")
    s = res["summary"]
    print(f"[*] 억제 {s['suppressed']} · 검토대상 {s['needs_review']} · 동적확증 {s['dynamic_confirmed']} · 심각도 {s['by_severity']}")
    print(f"[*] 결과 {out}/results.json  |  대시보드 {out}/index.html")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="sast", description="repo-무관 SAST+DAST (오프라인 우선, 계층형)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="repo 스캔 / 블랙박스 점검")
    sc.add_argument("target", nargs="?", default=None, help="스캔 대상 repo 경로(없으면 블랙박스만)")
    sc.add_argument("--out", required=True, help="결과 출력 폴더")
    sc.add_argument("--name", default=None, help="표시 이름(기본: 폴더명/호스트)")
    sc.add_argument("--online", action="store_true", help="개방망: 2·3계층(LLM) 활성화")
    sc.add_argument("--no-triage", action="store_true", help="1계층 오프라인 트리아지 끄기")
    sc.add_argument("--verify", default=None, metavar="URL", help="블랙박스: 라이브 URL 점검(수동)")
    sc.add_argument("--capture", default=None, metavar="FILE",
                    help="패시브 분석: Burp items XML/HAR 캡처(오프라인, 패킷0) → 엔드포인트 CSV+취약점")
    sc.add_argument("--active", action="store_true", help="경량 능동 DAST(내장, 인가 전용)")
    sc.add_argument("--okra", "--zap", dest="okra", action="store_true",
                    help="OKRA DAST(ZAP 엔진 spider+ascan + 중요정보 스캔, 인가 전용)")
    sc.add_argument("--cookie", default=None, help="DAST 요청 쿠키(예: 'PHPSESSID=..')")
    sc.add_argument("--header", action="append", default=[], metavar="'N: V'", help="DAST 커스텀 헤더(반복 가능)")
    sc.set_defaults(func=cmd_scan)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
