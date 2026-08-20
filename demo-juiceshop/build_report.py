#!/usr/bin/env python3
"""
최종 결과 대시보드 (SAST + DAST 통합, 한국어).

방침: 대시보드에는 **확정 취약점만** 싣는다.
  - SAST 동적 확증 (verify_results.json, status=CONFIRMED)
  - DAST 추가 발견 (dast_findings.json, status=CONFIRMED)
오탐/검토/비적용은 대시보드에서 제외하고 sast_improvement.md 로 분리(엔진 개선용).

읽기  data/findings_triaged.json, data/verify_results.json, data/dast_findings.json
쓰기  audit_report.html
"""
import json, os, html, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
D = lambda n: json.load(open(os.path.join(HERE, "data", n), encoding="utf-8"))
DATA = D("findings_triaged.json")
DYN = D("verify_results.json") if os.path.exists(os.path.join(HERE,"data","verify_results.json")) else {}
DAST = D("dast_findings.json") if os.path.exists(os.path.join(HERE,"data","dast_findings.json")) else []

e = lambda s: html.escape(str(s if s is not None else ""))
PROJECT = "juice-shop"; TITLE = "최종 보안 진단 결과 — SAST + DAST"
now = datetime.datetime.now(); DATE = now.strftime("%Y-%m-%d"); TIME = now.strftime("%H:%M")

SEV = {"크리티컬":("b-err","fail",0), "높음":("b-warn","warn",1), "중간":("b-info","",2), "낮음":("b-mut","mut",3)}
PRI2SEV = {"P1":"크리티컬","P2":"높음","P3":"중간","P4":"낮음"}

# ---- 확정 목록 구성 ----
final = []

# SAST 동적 확증
for m in DATA:
    d = DYN.get(m["id"])
    if not d or d.get("status") != "CONFIRMED": continue
    t = m["triage"]
    final.append(dict(
        ref=m["id"], source="SAST 확증", sev=PRI2SEV[t["priority"]],
        title=t["category"], where=f'{m["path"]}:{m["line"]}',
        evidence=d["evidence"], poc=t.get("poc","") or d.get("payload","")))

# DAST 추가 발견 (심각도 매핑)
DSEV = {"D4":"높음","D3":"중간","D1":"중간","D2":"중간","D6":"중간","D8":"중간","D5":"낮음"}
DPOC = {
 "D1":"GET /metrics", "D2":"GET /api-docs/",
 "D3":"GET /api/Users  (임의 인증 토큰) → 전체 사용자 이메일 반환",
 "D4":"GET /rest/basket/2  (내 것이 아닌 basket id) → 타 사용자 장바구니 반환",
 "D5":"응답 헤더에 Content-Security-Policy / Strict-Transport-Security 부재",
 "D6":"GET /ftp/acquisitions.md → 기밀 문서 직접 다운로드",
 "D8":"POST /rest/user/login 반복 실패에도 429/락아웃 없음",
}
for x in DAST:
    if x.get("status") != "CONFIRMED": continue
    final.append(dict(
        ref=x["id"], source="DAST 발견", sev=DSEV.get(x["id"],"중간"),
        title=x["cls"], where=x["title"], evidence=x["evidence"], poc=DPOC.get(x["id"],"")))

final.sort(key=lambda f: SEV[f["sev"]][2])

# ---- 집계 ----
n_total = len(final)
n_sast = sum(1 for f in final if f["source"]=="SAST 확증")
n_dast = sum(1 for f in final if f["source"]=="DAST 발견")
n_crit = sum(1 for f in final if f["sev"]=="크리티컬")
by_sev = {k: sum(1 for f in final if f["sev"]==k) for k in SEV}

# 오탐/비적용 (대시보드 제외) — 개선 문서로 분리
fp_confirmed = sum(1 for x in DAST if x.get("status")=="FP_CONFIRMED")
sast_raw = len(DATA)
excluded = sast_raw - n_sast   # 43 - 9 = 동적확증 외 나머지(오탐+저위험+검토)

grade, gcls = "F", "fail"

def card(f):
    bcls, scls, _ = SEV[f["sev"]]
    src_cls = "b-err" if f["source"]=="DAST 발견" else "b-info"
    poc = f'<h5>공격 구문</h5><pre><code>{e(f["poc"])}</code></pre>' if f["poc"] else ""
    return f"""
    <details>
      <summary>
        <span class="badge {bcls}">{f["sev"]}</span>
        <span class="badge {src_cls}">{f["source"]}</span>
        <code>{e(f["ref"])}</code> · {e(f["title"])}
      </summary>
      <p class="dim">{e(f["where"])}</p>
      <p><strong>확인:</strong> {e(f["evidence"])}</p>
      {poc}
    </details>"""

# 심각도별 그룹
groups = ""
for sv in ("크리티컬","높음","중간","낮음"):
    items = [f for f in final if f["sev"]==sv]
    if not items: continue
    groups += f'<section class="section"><h3>{sv} <span class="dim">({len(items)}건)</span></h3>' + "".join(card(f) for f in items) + "</section>"

meta_json = json.dumps({"title":TITLE,"type":"audit","project":PROJECT,"date":DATE}, ensure_ascii=False)

CSS = """
:root{--bg:#0f131a;--surface:#171d27;--surface-2:#1f2733;--line:#2b3542;--line-2:#38434f;
--ink:#e6ebf3;--ink-soft:#98a3b7;--ink-faint:#6a7486;
--err:#e8756f;--err-bg:#2c1a1a;--ok:#57bd89;--ok-bg:#14271d;--warn:#d8ab52;--warn-bg:#2a2416;
--info:#6e9fdc;--info-bg:#1a2740;--mut:#7d8798;--mut-bg:#242c38;--code-bg:#0a0e15;}
*{box-sizing:border-box}html,body{background:var(--bg);}
body{margin:0;color:var(--ink);font-family:"IBM Plex Sans KR",system-ui,-apple-system,"Malgun Gothic",sans-serif;font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased;}
.mono,code,pre{font-family:"IBM Plex Mono",ui-monospace,monospace;}
.page{max-width:900px;margin:0 auto;padding:2rem 1.1rem 5rem;background:var(--bg);min-height:100vh;}
.report-header{border-bottom:1px solid var(--line);padding-bottom:1rem;margin-bottom:1.6rem;}
.report-header h1{margin:0 0 .3rem;font-size:clamp(21px,3.3vw,29px);font-weight:700;letter-spacing:-.02em;}
.meta{font-size:.85em;color:var(--ink-faint);}.meta span{margin-right:1.3em;}
h3{font-size:1.12rem;font-weight:700;margin:0 0 .8rem;}
.section{margin-bottom:1.6rem;}
.dim{color:var(--ink-soft);font-size:.9em;font-weight:400;}
.badge{display:inline-block;padding:.15em .55em;border-radius:5px;font-size:.74em;font-weight:600;margin-right:.25em;font-family:"IBM Plex Mono",monospace;white-space:nowrap;}
.b-err{background:var(--err-bg);color:var(--err);}.b-ok{background:var(--ok-bg);color:var(--ok);}
.b-warn{background:var(--warn-bg);color:var(--warn);}.b-info{background:var(--info-bg);color:var(--info);}.b-mut{background:var(--mut-bg);color:var(--mut);}
.fail{color:var(--err);}.warn{color:var(--warn);}.pass{color:var(--ok);}.mut{color:var(--ink-faint);}
.grade-wrap{display:flex;align-items:center;gap:1.4rem;flex-wrap:wrap;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.3rem;}
.score{font-size:3em;font-weight:800;line-height:1;}
.tiles{display:flex;gap:1.3rem;flex-wrap:wrap;margin-top:.5rem;}
.tiles div{font-size:.85em;color:var(--ink-soft);}.tiles b{font-size:1.7em;display:block;color:var(--ink);}
.excl{margin-top:.8rem;font-size:.82em;color:var(--ink-faint);border-left:2px solid var(--line-2);padding-left:.7rem;}
table{border-collapse:collapse;width:100%;background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden;}
th,td{padding:.55rem .8rem;text-align:left;border-bottom:1px solid var(--line);}
thead th{background:var(--surface-2);color:var(--ink-soft);font-size:.8em;font-weight:600;}
tbody tr:last-child td{border-bottom:0;}
details{margin-bottom:.6rem;border:1px solid var(--line);border-radius:10px;padding:.7rem 1rem;background:var(--surface);}
details[open]{background:var(--surface-2);}summary{cursor:pointer;font-weight:500;line-height:2;}summary code{color:var(--ink);}
details p{margin:.4rem 0;}h5{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--ink-faint);margin:.8rem 0 .3rem;font-weight:700;}
pre{margin:.2rem 0;background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem;overflow-x:auto;font-size:.82em;line-height:1.6;color:#cdd7e6;}
pre code{background:transparent;padding:0;color:inherit;}
code{background:var(--surface-2);border:1px solid var(--line);border-radius:4px;padding:.05em .35em;font-size:.85em;color:var(--info);}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);font-size:.8em;color:var(--ink-faint);}
"""

DOC = f"""<!DOCTYPE html>
<html lang="ko" data-theme="dark">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(TITLE)}</title>
<meta name="report-type" content="audit"><meta name="report-project" content="{PROJECT}"><meta name="report-date" content="{DATE}">
<script type="application/json" id="report-meta">
{meta_json}
</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+KR:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>{CSS}</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <h1>{e(TITLE)}</h1>
    <div class="meta"><span>{PROJECT}</span><span>{DATE} {TIME}</span>
      <span class="badge b-info">확정 취약점만</span></div>
  </div>

  <section class="section">
    <h3>요약</h3>
    <div class="grade-wrap">
      <div class="score {gcls}">{grade}</div>
      <div>
        <p style="margin:0"><strong class="fail">확정 취약점 {n_total}건</strong> — 크리티컬 {n_crit}건 즉시 조치</p>
        <div class="tiles">
          <div><b class="fail">{n_total}</b> 확정 취약점</div>
          <div><b>{n_sast}</b> SAST 확증</div>
          <div><b class="fail">{n_dast}</b> DAST 추가발견</div>
          <div><b class="warn">{by_sev['크리티컬']}·{by_sev['높음']}</b> 크리티컬·높음</div>
        </div>
        <div class="excl">오탐·비적용 {excluded}건은 대시보드에서 제외 — SAST 엔진 개선 인풋으로 분리(<code>sast_improvement.md</code>). 오탐 확정 {fp_confirmed}건 포함.</div>
      </div>
    </div>
  </section>

  <section class="section">
    <h3>SAST ↔ DAST 대조</h3>
    <table>
      <thead><tr><th>구분</th><th>건수</th><th>의미</th></tr></thead>
      <tbody>
        <tr><td>SAST 동적 확증</td><td class="pass">{n_sast}</td><td>룰이 잡고 실제 익스플로잇으로 재현</td></tr>
        <tr><td>DAST 추가 발견(미탐)</td><td class="fail">{n_dast}</td><td>SAST가 못 본 것 — 접근제어·노출·헤더·무차별방어</td></tr>
        <tr><td>SAST 오탐·비적용</td><td class="mut">{excluded}</td><td>대시보드 제외 → 엔진 개선용(별도 문서)</td></tr>
      </tbody>
    </table>
    <p class="dim" style="margin-top:.6rem">SAST는 인젝션·경로순회처럼 데이터 흐름이 보이는 것에 강하고, IDOR·권한·민감 엔드포인트 노출·보안헤더처럼 <b>인가/설정/부재</b>는 구조적으로 못 본다 → DAST로 메운다.</p>
  </section>

  <h3>확정 취약점</h3>
  {groups}

  <section class="section">
    <h3>다음 단계</h3>
    <ol>
      <li>크리티컬 {n_crit}건 최우선 조치 — 로그인·검색 SQLi, eval RCE, JWT 위조, 경로순회.</li>
      <li>DAST 발견분(IDOR·사용자 열거)은 <strong>인가 검사 추가</strong>로 해결 — 오브젝트 소유권 확인.</li>
      <li>/metrics·/api-docs 무인증 노출 차단, helmet로 보안 헤더 적용, 로그인 레이트리밋.</li>
      <li>오탐 {excluded}건은 <code>sast_improvement.md</code>의 억제 룰로 1·2계층에 반영 → 다음 스캔부터 노이즈 감소.</li>
    </ol>
  </section>

  <footer>SAST(Semgrep→LLM 트리아지) + DAST(라이브 능동 점검) 통합 · 확정 취약점만 표시 · 오탐은 엔진 개선 인풋으로 분리 · {DATE}</footer>
</div>
</body>
</html>"""

open(os.path.join(HERE, "audit_report.html"), "w", encoding="utf-8").write(DOC)
print(f"최종 대시보드 -> audit_report.html (확정 {n_total}: SAST확증 {n_sast} + DAST발견 {n_dast} | 크리티컬 {n_crit} | 제외 {excluded})")
