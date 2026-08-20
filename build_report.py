#!/usr/bin/env python3
"""
SAST 대시보드를 audit 리포트(한국어)로 빌드.

/report 스킬의 규약(data-theme, report-meta 인덱싱 블록, audit 구조)은 유지하되
테마 일관성을 위해 PicoCSS 대신 자체완결 다크 CSS 를 사용한다(아티팩트에서 흰색
구간이 생기던 문제 해결). 배경/색은 모두 명시적으로 칠한다.

읽기  data/findings_triaged.json, data/verify_results.json(있으면)
쓰기  audit_report.html
"""
import json, os, html, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = json.load(open(os.path.join(HERE, "data", "findings_triaged.json"), encoding="utf-8"))
DYN = {}
_vp = os.path.join(HERE, "data", "verify_results.json")
if os.path.exists(_vp):
    DYN = json.load(open(_vp, encoding="utf-8"))
dyn_confirmed = sum(1 for v in DYN.values() if v.get("status") == "CONFIRMED")

PROJECT = "juice-shop"
TITLE = "Juice Shop SAST 보안 감사"
now = datetime.datetime.now()
DATE = now.strftime("%Y-%m-%d"); TIME = now.strftime("%H:%M")
e = lambda s: html.escape(str(s if s is not None else ""))

# ---- 표시용 한국어 라벨 ----
VLABEL = {"TRUE_POSITIVE": "실제 취약점", "FALSE_POSITIVE": "오탐", "NEEDS_REVIEW": "검토 필요"}
TIER = {"P1": "크리티컬", "P2": "높음", "P3": "중간", "P4": "낮음/정보"}
EXP = {"HIGH": "높음", "MEDIUM": "중간", "LOW": "낮음", "NONE": "없음"}
DYNL = {"CONFIRMED": "✓ 동적 확증됨", "MANUAL": "◐ 수동 검증 예정", "NOT_CONFIRMED": "미재현"}

# ---- 집계 ----
def c(key, val): return sum(1 for m in DATA if m["triage"][key] == val)
tp, fp, nr = c("verdict","TRUE_POSITIVE"), c("verdict","FALSE_POSITIVE"), c("verdict","NEEDS_REVIEW")
p1, p2, p3, p4 = c("priority","P1"), c("priority","P2"), c("priority","P3"), c("priority","P4")
total = len(DATA)

if p1 > 0:   grade, gcls, gtext = "F", "fail", f"P1 크리티컬 {p1}건 — 즉시 조치 필요 · {dyn_confirmed}건 실제 익스플로잇으로 동적 확증"
elif p2 > 0: grade, gcls, gtext = "D", "warn", f"높음(P2) {p2}건 미해결"
elif p3 > 0: grade, gcls, gtext = "C", "warn", "중간 이슈만 존재"
else:        grade, gcls, gtext = "B", "pass", "유의미한 이슈 없음"

VCLS = {"TRUE_POSITIVE":"b-err", "FALSE_POSITIVE":"b-ok", "NEEDS_REVIEW":"b-warn"}
PCLS = {"P1":"b-err", "P2":"b-warn", "P3":"b-info", "P4":"b-mut"}
DCLS = {"CONFIRMED":"b-err", "MANUAL":"b-info", "NOT_CONFIRMED":"b-warn"}
PORD = {"P1":0,"P2":1,"P3":2,"P4":3}
order = sorted(DATA, key=lambda m:(PORD[m["triage"]["priority"]], -m["triage"]["confidence"]))

# ---- 상세 findings ----
def finding_html(m):
    t = m["triage"]
    d = DYN.get(m["id"]); dyn_summary = dyn_detail = ""
    if d:
        dyn_summary = f' <span class="badge {DCLS.get(d["status"],"b-info")}">{e(DYNL.get(d["status"], d["status"]))}</span>'
        httpline = f' → HTTP {d["http"]}' if d.get("http") else ""
        dyn_detail = (f'<h5>🎯 동적 검증{httpline}</h5>'
                      f'<p><strong>{e(d["status"])}</strong> — {e(d["evidence"])}</p>'
                      f'<pre><code>{e(d.get("payload",""))}</code></pre>')
    poc = f'<h5>⚔ 공격 예시 (PoC)</h5><pre><code>{e(t["poc"])}</code></pre>' if t.get("poc") else ""
    tags = " ".join(f'<span class="badge b-mut">{e(x.split(":")[0])}</span>' for x in (m.get("cwe") or [])) + " " + \
           " ".join(f'<span class="badge b-mut">{e(x.split(" - ")[0])}</span>' for x in (m.get("owasp") or []))
    note = f'<div class="note"><strong>트리아지 노트:</strong> {e(t["triage_note"])}</div>' if t.get("triage_note") else ""
    reach = "" if t["reachable"]!="false" else ' <span class="badge b-mut">도달 불가</span>'
    expcls = "fail" if t["exploitability"]=="HIGH" else "warn" if t["exploitability"]=="MEDIUM" else "mut"
    return f"""
    <details>
      <summary>
        <span class="badge {PCLS[t['priority']]}">{t['priority']}</span>
        <span class="badge {VCLS[t['verdict']]}">{e(VLABEL[t['verdict']])}</span>
        <code>{e(m['id'])}</code> · {e(t['category'])} — <code>{e(m['path'])}:{m['line']}</code>{reach}{dyn_summary}
      </summary>
      <p class="dim">{e(m['rule'])} &nbsp;|&nbsp; 악용가능성 <b class="{expcls}">{e(EXP[t['exploitability']])}</b> · 신뢰도 {t['confidence']:.2f} · 엔진 심각도 {e(m['severity'])}</p>
      <h5>코드 컨텍스트</h5>
      <pre><code>{e(m['code'])}</code></pre>
      <p><strong>판정 근거:</strong> {e(t['rationale'])}</p>
      <p><strong>증거:</strong> <code class="evi">{e(t['evidence'])}</code></p>
      {poc}
      {dyn_detail}
      <p><strong>수정 방안:</strong> {e(t['suggested_fix'])}</p>
      {note}
      <p>{tags}</p>
    </details>"""

sections = []
for pr in ("P1","P2","P3","P4"):
    items = [m for m in order if m["triage"]["priority"]==pr]
    if not items: continue
    sections.append(f'<section class="section"><h3>{pr} — {TIER[pr]} <span class="dim">({len(items)}건)</span></h3>' +
                    "".join(finding_html(m) for m in items) + "</section>")

rows = "".join(
    f"<tr><td><span class='badge {PCLS[pr]}'>{pr}</span></td><td>{TIER[pr]}</td>"
    f"<td class='{'fail' if pr=='P1' else 'warn' if pr in ('P2','P3') else 'mut'}'>{c('priority',pr)}</td></tr>"
    for pr in ("P1","P2","P3","P4"))

# ---- 동적 검증(DAST 브리지) 섹션 ----
byid = {m["id"]: m for m in DATA}
dyn_section = ""
if DYN:
    conf_rows = ""
    for fid, d in sorted(DYN.items()):
        t = byid.get(fid, {}).get("triage", {})
        sc = "fail" if d["status"]=="CONFIRMED" else ("warn" if d["status"]=="NOT_CONFIRMED" else "mut")
        icon = "✓" if d["status"]=="CONFIRMED" else ("◐" if d["status"]=="MANUAL" else "✗")
        conf_rows += (f"<tr><td><code>{e(fid)}</code></td><td>{e(t.get('category',''))}</td>"
                      f"<td class='{sc}'>{icon} {e(d['status'])}</td><td>{e(d['evidence'])}</td></tr>")
    dyn_section = f"""
    <section class="section">
      <h3>동적 검증 — DAST 브리지 <span class="dim">({dyn_confirmed}건 확증)</span></h3>
      <p class="dim">트리아지에서 확인된 각 finding 의 PoC 를 라이브 인스턴스(<code>http://localhost:3000</code>)에
      실제로 재생했다. 재현된 항목은 <strong>동적 확증</strong>으로 승격 — 정적 추론이 아니라 실행된 익스플로잇이다.</p>
      <table>
        <thead><tr><th>ID</th><th>유형</th><th>결과</th><th>증거</th></tr></thead>
        <tbody>{conf_rows}</tbody>
      </table>
    </section>"""

recommend = """
<ol>
  <li><strong>P1 5건을 최우선 조치</strong> — 로그인·검색 SQL 인젝션, <code>eval()</code> 코드 인젝션, null-byte 경로순회, 리포지토리 내 JWT 서명키. 모두 외부에서 도달 가능하고 영향이 큼.</li>
  <li><strong>모든 SQL 파라미터화</strong> — 문자열로 만든 <code>sequelize.query()</code> 를 바인드 파라미터로 교체.</li>
  <li><strong>시크릿을 리포지토리 밖으로</strong> — RSA 개인키를 시크릿 저장소/HSM 에서 로드하고 커밋된 키 교체.</li>
  <li><strong>P1 을 동적으로 확인</strong> — 위 공격 예시는 그대로 검증용 페이로드(DAST 계층 브리지).</li>
  <li><strong>오탐 6건과 대부분의 P4 는 노이즈</strong> — 설계상 퍼블릭 서브넷, <code>_correct.tf</code> 참조 파일, CI 하드닝 힌트. 룰 단에서 억제해 신호를 유지.</li>
</ol>"""

meta_json = json.dumps({"title":TITLE,"type":"audit","project":PROJECT,"date":DATE}, ensure_ascii=False)

CSS = """
:root{
  --bg:#0f131a; --surface:#171d27; --surface-2:#1f2733; --line:#2b3542; --line-2:#38434f;
  --ink:#e6ebf3; --ink-soft:#98a3b7; --ink-faint:#6a7486;
  --err:#e8756f; --err-bg:#2c1a1a; --ok:#57bd89; --ok-bg:#14271d; --warn:#d8ab52; --warn-bg:#2a2416;
  --info:#6e9fdc; --info-bg:#1a2740; --mut:#7d8798; --mut-bg:#242c38;
  --code-bg:#0a0e15;
}
*{box-sizing:border-box}
html,body{background:var(--bg);}
body{margin:0;color:var(--ink);
  font-family:"IBM Plex Sans KR",system-ui,-apple-system,"Malgun Gothic",sans-serif;
  font-size:15px;line-height:1.6;-webkit-font-smoothing:antialiased;}
.page{max-width:940px;margin:0 auto;padding:2rem 1.1rem 5rem;background:var(--bg);min-height:100vh;}
.mono,code,pre{font-family:"IBM Plex Mono",ui-monospace,monospace;}
a{color:var(--info);}
.report-header{border-bottom:1px solid var(--line);padding-bottom:1rem;margin-bottom:1.6rem;}
.report-header h1{margin:0 0 .3rem;font-size:clamp(22px,3.4vw,30px);font-weight:700;letter-spacing:-.02em;}
.meta{font-size:.85em;color:var(--ink-faint);} .meta span{margin-right:1.3em;}
h3{font-size:1.15rem;font-weight:700;margin:0 0 .8rem;letter-spacing:-.01em;}
.section{margin-bottom:1.7rem;}
.dim{color:var(--ink-soft);font-size:.9em;font-weight:400;}
.badge{display:inline-block;padding:.15em .55em;border-radius:5px;font-size:.75em;font-weight:600;margin-right:.25em;
  font-family:"IBM Plex Mono",monospace;white-space:nowrap;}
.b-err{background:var(--err-bg);color:var(--err);} .b-ok{background:var(--ok-bg);color:var(--ok);}
.b-warn{background:var(--warn-bg);color:var(--warn);} .b-info{background:var(--info-bg);color:var(--info);}
.b-mut{background:var(--mut-bg);color:var(--mut);}
.fail{color:var(--err);} .warn{color:var(--warn);} .pass{color:var(--ok);} .mut{color:var(--ink-faint);}
.grade-wrap{display:flex;align-items:center;gap:1.4rem;flex-wrap:wrap;
  background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:1.1rem 1.3rem;}
.score{font-size:3em;font-weight:800;line-height:1;}
.tiles{display:flex;gap:1.3rem;flex-wrap:wrap;margin-top:.5rem;}
.tiles div{font-size:.85em;color:var(--ink-soft);} .tiles b{font-size:1.7em;display:block;color:var(--ink);}
table{border-collapse:collapse;width:100%;background:var(--surface);border:1px solid var(--line);border-radius:10px;overflow:hidden;}
th,td{padding:.55rem .8rem;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;}
thead th{background:var(--surface-2);color:var(--ink-soft);font-size:.8em;font-weight:600;letter-spacing:.03em;}
tbody tr:last-child td{border-bottom:0;}
details{margin-bottom:.6rem;border:1px solid var(--line);border-radius:10px;padding:.7rem 1rem;background:var(--surface);}
details[open]{background:var(--surface-2);}
summary{cursor:pointer;font-weight:500;line-height:2;}
summary code{color:var(--ink);}
details p{margin:.4rem 0;} details p.dim{margin:.2rem 0 .6rem;}
h5{font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;color:var(--ink-faint);margin:.9rem 0 .3rem;font-weight:700;}
pre{margin:.2rem 0;background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem;overflow-x:auto;font-size:.8em;line-height:1.65;color:#cdd7e6;}
pre code{background:transparent;padding:0;color:inherit;}
code{background:var(--surface-2);border:1px solid var(--line);border-radius:4px;padding:.05em .35em;font-size:.85em;color:var(--info);}
code.evi{display:inline-block;color:var(--ink);}
.note{border-left:3px solid var(--warn);background:var(--warn-bg);padding:.5rem .8rem;border-radius:0 7px 7px 0;font-size:.88em;margin:.5rem 0;}
footer{margin-top:2.5rem;padding-top:1rem;border-top:1px solid var(--line);font-size:.8em;color:var(--ink-faint);}
"""

DOC = f"""<!DOCTYPE html>
<html lang="ko" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(TITLE)}</title>
<meta name="report-type" content="audit">
<meta name="report-project" content="{PROJECT}">
<meta name="report-date" content="{DATE}">
<script type="application/json" id="report-meta">
{meta_json}
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+KR:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">
<style>{CSS}</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <h1>{e(TITLE)}</h1>
    <div class="meta">
      <span>{PROJECT}</span><span>{DATE} {TIME}</span>
      <span class="badge b-info">audit</span>
      <span class="badge b-info">Semgrep → LLM 트리아지 → 동적검증</span>
    </div>
  </div>

  <section class="section">
    <h3>종합 평가</h3>
    <div class="grade-wrap">
      <div class="score {gcls}">{grade}</div>
      <div>
        <p style="margin:0"><strong class="{gcls}">{e(gtext)}</strong></p>
        <div class="tiles">
          <div><b>{total}</b> 원시 탐지</div>
          <div><b class="fail">{tp}</b> 실제 취약점</div>
          <div><b class="warn">{nr}</b> 검토 필요</div>
          <div><b class="pass">{fp}</b> 오탐</div>
          <div><b>{round(tp/total*100) if total else 0}%</b> 신호비율</div>
          <div><b class="fail">{dyn_confirmed}</b> 동적 확증</div>
        </div>
      </div>
    </div>
  </section>

  <section class="section">
    <h3>우선순위 요약</h3>
    <table>
      <thead><tr><th>우선순위</th><th>등급</th><th>건수</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>

  {dyn_section}

  <h3>상세 취약점</h3>
  {''.join(sections)}

  <section class="section">
    <h3>권고 사항</h3>
    {recommend}
  </section>

  <footer>
    2계층 SAST(Semgrep 룰 엔진 → 스키마 강제 LLM 트리아지) + 동적 검증 · 공격 예시는 인가된 OWASP Juice Shop 훈련 타깃에 대한 검증 페이로드 · 생성일 {DATE}
  </footer>
</div>
</body>
</html>"""

open(os.path.join(HERE, "audit_report.html"), "w", encoding="utf-8").write(DOC)
print(f"audit 리포트 -> audit_report.html  (등급 {grade}: TP={tp} FP={fp} NR={nr} | P1={p1} P2={p2} P3={p3} P4={p4} | 동적확증 {dyn_confirmed})")
