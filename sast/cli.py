"""SAST CLI 진입점.  python3 -m sast scan <target> --out <dir>"""
import argparse, os, sys
from .engines import run_all
from . import triage, crossval, dynamic, report

def cmd_scan(a):
    target = os.path.abspath(a.target)
    if not os.path.isdir(target):
        print(f"경로가 없습니다: {target}"); return 2
    name = a.name or os.path.basename(target.rstrip("/\\"))
    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)

    print(f"[*] 스캔: {target}")
    findings, engines = run_all(target, out)
    if not engines:
        print("[!] 사용 가능한 엔진이 없습니다 (semgrep 설치 필요)"); return 3
    print(f"[*] 엔진: {', '.join(engines)}  원시 {len(findings)}건")

    # 2계층 — 오프라인 트리아지(억제/심각도) + 엔진 교차검증. 기본 on, SAST_NO_TRIAGE=1 로 off.
    layers = ["layer1"]
    if a.no_triage or os.environ.get("SAST_NO_TRIAGE"):
        print("[*] 2계층(트리아지) OFF")
    else:
        rules = triage.load_rules()
        triage.apply(findings, rules)
        crossval.apply(findings, rules)
        layers.append("triage")

    # 3계층 — 동적 검증/DAST 브릿지. 라이브 URL 있을 때만 켜짐. SAST_NO_VERIFY=1 로 off.
    verify_url = a.verify or os.environ.get("SAST_VERIFY_URL")
    if verify_url and not os.environ.get("SAST_NO_VERIFY"):
        findings = dynamic.verify(findings, verify_url)
        layers.append("dast")
    elif verify_url:
        print("[*] 3계층(동적검증) OFF")

    res = report.build(name, target, engines, findings, out, mode="+".join(layers))
    s = res["summary"]
    print(f"[*] 억제 {s['suppressed']} · 검토대상 {s['needs_review']} · 심각도 {s['by_severity']}")
    print(f"[*] 결과 {out}/results.json  |  대시보드 {out}/index.html")
    return 0

def main(argv=None):
    p = argparse.ArgumentParser(prog="sast", description="repo-무관 SAST (오프라인, 모듈형)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="repo 스캔")
    sc.add_argument("target", help="스캔 대상 repo 경로")
    sc.add_argument("--out", required=True, help="결과 출력 폴더")
    sc.add_argument("--name", default=None, help="표시 이름(기본: 폴더명)")
    sc.add_argument("--no-triage", action="store_true", help="2계층(트리아지) 끄기")
    sc.add_argument("--verify", default=None, metavar="URL", help="3계층: 라이브 URL 동적검증")
    sc.set_defaults(func=cmd_scan)
    a = p.parse_args(argv)
    return a.func(a)

if __name__ == "__main__":
    sys.exit(main())
