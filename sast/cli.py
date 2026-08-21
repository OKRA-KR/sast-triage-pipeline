"""SAST+DAST CLI 진입점.

Track A (Repo 있음)  → SAST:  1계층(오프라인 룰+트리아지) → 2계층(LLM 트리아지) → 3계층(LLM 심화)
Track B (Repo 없음)  → 블랙박스: 라이브 URL 엔드포인트 식별 → 공격 가능 포인트

환경 게이팅: 기본 폐쇄망(offline) → 2·3계층 OFF. `--online`(SAST_ONLINE) + LLM 설정 시만 ON.
  python3 -m sast scan <target> --out <dir> [--online] [--verify <URL>] [--no-triage]
"""
import argparse, os, sys
from .engines import run_all
from . import triage, crossval, layer2, layer3, blackbox, report, env


def cmd_scan(a):
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    verify_url = a.verify or os.environ.get("SAST_VERIFY_URL")
    if a.online:
        os.environ["SAST_ONLINE"] = "1"

    target = os.path.abspath(a.target) if a.target else None
    have_repo = bool(target and os.path.isdir(target))
    name = a.name or (os.path.basename(target.rstrip("/\\")) if have_repo
                      else (verify_url.split("//")[-1].split("/")[0] if verify_url else "scan"))

    findings, engines, layers = [], [], []

    # ── Track A : SAST (Repo 있음) ──────────────────────────────
    if have_repo:
        print(f"[*] 스캔: {target}   (환경: {env.mode_label()})")
        findings, engines = run_all(target, out)
        if not engines:
            print("[!] 사용 가능한 엔진이 없습니다 (semgrep 설치 필요)"); return 3
        print(f"[*] 엔진: {', '.join(engines)}  원시 {len(findings)}건")
        layers.append("layer1")

        # 1계층 내부: 오프라인 트리아지(억제/심각도) + 교차검증 (외부통신 없음)
        if a.no_triage or os.environ.get("SAST_NO_TRIAGE"):
            print("[*] 오프라인 트리아지 OFF")
        else:
            rules = triage.load_rules()
            triage.apply(findings, rules)
            crossval.apply(findings, rules)

        # 2계층: LLM 트리아지 (개방망 전용)
        if env.layer2_enabled():
            findings = layer2.triage(findings); layers.append("llm-triage")
        elif env.is_online():
            print("[*] 2계층(LLM 트리아지) 건너뜀 — LLM 미설정(SAST_LLM_KEY)")
        else:
            print("[*] 2계층(LLM 트리아지) OFF — 폐쇄망")

        # 3계층: LLM 심화 (개방망 전용)
        if env.layer3_enabled():
            findings = layer3.deepen(findings); layers.append("llm-deepen")
    elif not verify_url:
        print(f"[!] 대상 경로가 없고 --verify 도 없습니다: {a.target}"); return 2

    # ── Track B : 블랙박스 (라이브 URL) ─────────────────────────
    if verify_url and not os.environ.get("SAST_NO_VERIFY"):
        findings = blackbox.probe(findings, verify_url)
        layers.append("blackbox")

    src = target if have_repo else (verify_url or "")
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
    sc.add_argument("--verify", default=None, metavar="URL", help="블랙박스: 라이브 URL 점검")
    sc.set_defaults(func=cmd_scan)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
