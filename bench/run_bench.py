#!/usr/bin/env python3
"""정답셋(ground-truth) 벤치마크 — 스캐너의 정밀도/재현율 측정 (P1-1).

스캔 결과(results.json)를 bench/expected/<name>.json 의 정답과 대조해
카테고리별 TP/FN, recall, clean 범위 FP 를 출력하고 baseline 과 회귀 비교한다.

사용:
  python3 bench/run_bench.py vulnphp            # 합성 타깃 스캔→측정(정답 정확)
  python3 bench/run_bench.py webgoat            # 기존 results.json 대조(레슨 기반 recall)
  python3 bench/run_bench.py vulnphp --update-baseline

정답 정의(bench/expected/<name>.json):
  scan_target: 스캔할 경로(있으면 스캔) | results: 기존 results.json 경로(있으면 재사용)
  expected[]: {category, path}     — 해당 카테고리 finding 이 path 를 포함하면 recall hit
  clean[]:    {group, path}        — 해당 group finding 이 path 를 포함하면 FP
stdlib 전용.
"""
import json, os, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "bench")
sys.path.insert(0, ROOT)
from sast.schema import group_of   # noqa: E402


def _load_results(spec, name):
    if spec.get("results"):
        p = os.path.join(ROOT, spec["results"])
        if not os.path.exists(p):
            sys.exit(f"[!] results 없음: {p} — 먼저 스캔 필요")
        return json.load(open(p, encoding="utf-8"))
    tgt = os.path.join(ROOT, spec["scan_target"])
    out = os.path.join(tempfile.gettempdir(), "bench_" + name)
    print(f"[*] 스캔: {tgt}")
    env = dict(os.environ, SAST_NO_SCA="1")     # 벤치 결정성: 의존성 CVE 스킵
    r = subprocess.run([sys.executable, "-m", "sast", "scan", tgt, "--out", out, "--name", name],
                       cwd=ROOT, env=env)
    if r.returncode != 0:
        sys.exit(f"[!] 스캔 실패(rc={r.returncode})")
    return json.load(open(os.path.join(out, "results.json"), encoding="utf-8"))


def _norm(p):
    return (p or "").replace("\\", "/")


def evaluate(spec, results):
    findings = results["findings"]
    rows, tp, fn = [], 0, 0
    for e in spec["expected"]:
        hits = [f for f in findings if f["category"] == e["category"] and e["path"] in _norm(f["file"])]
        ok = len(hits) > 0
        tp += ok; fn += (not ok)
        rows.append((e["category"], e["path"], len(hits), "HIT" if ok else "MISS"))
    fp_rows, fp = [], 0
    for c in spec.get("clean", []):
        bad = [f for f in findings if group_of(f["category"]) == c["group"] and c["path"] in _norm(f["file"])]
        fp += len(bad)
        fp_rows.append((c["group"], c["path"], len(bad)))
    recall = tp / len(spec["expected"]) if spec["expected"] else 0.0
    # precision 근사: 정답 히트 / (정답 히트 + clean-FP)  (부분 정답이라 clean 범위로만 측정)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    return dict(rows=rows, fp_rows=fp_rows, tp=tp, fn=fn, fp=fp,
                recall=round(recall, 3), precision=round(precision, 3),
                total_findings=len(findings))


def _print(name, m):
    print(f"\n=== 벤치: {name} ===")
    print(f"{'category':<20}{'expected-path':<32}{'found':>6}  결과")
    for cat, path, n, r in m["rows"]:
        print(f"{cat:<20}{path:<32}{n:>6}  {r}")
    if m["fp_rows"]:
        print("\n[clean 범위 FP]")
        for g, path, n in m["fp_rows"]:
            print(f"  group={g:<14} {path:<30} FP={n}")
    print(f"\nrecall={m['recall']}  precision(clean범위)={m['precision']}  "
          f"TP={m['tp']} FN={m['fn']} FP={m['fp']}  총 finding={m['total_findings']}")


def main():
    if len(sys.argv) < 2:
        sys.exit("사용: python3 bench/run_bench.py <name> [--update-baseline]")
    name = sys.argv[1]
    spec = json.load(open(os.path.join(BENCH, "expected", name + ".json"), encoding="utf-8"))
    m = evaluate(spec, _load_results(spec, name))
    _print(name, m)

    bpath = os.path.join(BENCH, "baseline.json")
    baseline = json.load(open(bpath, encoding="utf-8")) if os.path.exists(bpath) else {}
    cur = {"recall": m["recall"], "precision": m["precision"], "fn": m["fn"], "fp": m["fp"]}
    if "--update-baseline" in sys.argv:
        baseline[name] = cur
        json.dump(baseline, open(bpath, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
        print(f"\n[*] baseline 갱신: {name} = {cur}")
        return 0
    prev = baseline.get(name)
    if prev:
        reg = m["recall"] < prev["recall"] - 1e-9 or m["fp"] > prev["fp"]
        print(f"\n[baseline] 이전 {prev} → 현재 {cur}  "
              + ("⚠ 회귀(재현율↓ 또는 FP↑)" if reg else "OK(회귀 없음)"))
        return 1 if reg else 0
    print("\n[baseline] 없음 — --update-baseline 로 기준선 저장")
    return 0


if __name__ == "__main__":
    sys.exit(main())
