# SAST — repo-무관 모듈형 스캐너 (오프라인)

Semgrep 룰 엔진 + 데이터 기반 오탐 억제 + 고정 스키마 결과 + 자체완결 대시보드.
**폐쇄망 우선**: 코어는 stdlib만, LLM 불필요. CodeQL 등 엔진을 끼울 슬롯 준비됨.

## 빠른 사용

```bash
# WSL/Kali (semgrep 은 pipx install semgrep)
./sast-run.sh <대상>            # 기본: Semgrep (빠름, 오프라인)
./sast-run.sh <대상> --deep     # + CodeQL taint/dataflow (느림, CodeQL CLI 필요)
#   <대상> = 로컬경로 | git URL | owner/repo | targets/ 폴더명
```

**엔진 조합**: 기본은 Semgrep(패턴, 빠름). `--deep`은 CodeQL(taint 기반)을 더해 Semgrep이
못 보는 흐름 취약점(레이트리밋 부재·경로/프로토타입 오염·정보 노출 등)을 잡는다.
CodeQL CLI 위치는 `CODEQL_HOME` 또는 PATH, 없으면 `~/codeql`.

또는 Windows에서 `sast-run.bat` 더블클릭 → 대상 입력.

결과: `out/<name>/results.json` + `out/<name>/index.html`(더블클릭, 오프라인).
다른 repo 결과는 `dashboard.template.html`에 `results.json`을 **드래그드롭**해서 봄.

## 구조

```
sast/                     코어 (stdlib 전용, 오프라인)
  engines/
    __init__.py           엔진 레지스트리 + run_all (fingerprint 로 dedup 병합)
    semgrep_engine.py     Semgrep 어댑터 (기본)
    codeql_engine.py      CodeQL 어댑터 (--deep, taint/dataflow)
  rules/
    suppress.json         오탐 억제/심각도 룰 라이브러리 (데이터 — 코드 수정 없이 확장)
  schema.py               통합 finding 스키마 + categorize/fingerprint
  triage.py               suppress.json 적용: 억제 + 심각도 (LLM 불필요)
  report.py               results.json(sast-results/2) + 대시보드 생성
  cli.py                  python3 -m sast scan <target> --out <dir>
dashboard.template.html   넓은(1400px) 자체완결 뷰어
sast-run.sh / .bat        실행자 트리거 러너 (clone→scan)
out/ , targets/           생성물 / 클론 대상 (git 제외)
```

## 설계 원칙 (목표 매핑)

- **오탐 최소화(지속)** → `rules/suppress.json`을 계속 늘림. 각 룰이 근거를 가짐. 코드 안 건드림.
- **폐쇄망 맨먼스↓** → 코어 stdlib만, LLM 없이 1계층에서 억제+심각도까지. CodeQL(오프라인 dataflow) 슬롯 준비.
- **쉬운 사용** → 대상 하나만 주면 clone·scan·대시보드 자동.
- **깔끔한 출력** → 단일 고정 스키마 → 어떤 repo든 같은 대시보드.
- **우회/2차피해 고도화** → 엔진(engines/)·룰(suppress.json)·동적 검증 모듈을 계속 추가.

## 확장 지점

| 하고 싶은 것 | 건드릴 곳 |
|---|---|
| 엔진 추가 (CodeQL/gosec/gitleaks) | `sast/engines/<new>.py` 만들고 `engines/__init__.py`의 `ENGINES`에 등록 |
| 오탐 룰 추가 | `sast/rules/suppress.json` (path_suppress / rule_suppress / downgrade) |
| 심각도 정책 | `suppress.json`의 `severity_by_category` |
| 대시보드 UI | `dashboard.template.html` |
| 온라인 LLM 트리아지 | `results.json`의 `verdict`/`rationale` 필드에 채우는 별도 단계 |
| 동적 검증(우회/RCE) | 별도 검증 모듈 → finding의 `dynamic` 필드 채움 |

## 스키마 (sast-results/2)

`results.json` = `{ meta, summary, findings[] }`. finding 주요 필드:
`id, fingerprint, engines[], rule, category, severity, verdict, confidence,
file, line, cwe[], owasp[], code, message, rationale, evidence, poc,
reachable, source, dynamic, suppressed, suppress_reason`.
