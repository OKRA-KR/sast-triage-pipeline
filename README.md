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
지원 언어: JavaScript/TypeScript · Python · **Java**(`--build-mode=none` 소스추출, Maven/Gradle 빌드 불필요).
CodeQL CLI 위치는 `CODEQL_HOME` 또는 PATH, 없으면 `~/codeql`. DB 는 임시 fs 에 생성 후 삭제,
SARIF 만 `out/<name>/codeql.sarif` 에 남는다(`CODEQL_DB_DIR`, `CODEQL_RAM` 로 조정).

**SCA(의존성 CVE, sca)**: `osv-scanner`(단일 바이너리 + 오프라인 OSV DB)를 감싸 lockfile/manifest
(package-lock.json·pom.xml·requirements.txt·go.mod 등)의 **알려진 CVE**를 탐지한다(OWASP A06 / 취약 컴포넌트).
9P 마운트에서 osv 재귀 walk 가 lockfile 을 못 찾는 문제를 피하려 파이썬으로 lockfile 을 찾아 `-L` 로 넘긴다.
CVSS 기반 심각도, 수정본 버전, CVE 태그 포함. CLI 위치: `OSV_SCANNER` > PATH > `~/osv-scanner`.
폐쇄망: `SAST_OSV_OFFLINE=1`(사전 다운로드 DB). osv-scanner 없으면 자동 스킵. 끄기 `SAST_NO_SCA=1`.

**중요정보 스캐너(secrets-scan)**: 기본 내장 엔진(stdlib 정규식, 오프라인, 외부툴 불필요).
평문 시크릿·자격증명·규제 개인정보를 탐지한다 — GitHub PAT·AWS키·Google/Slack/Stripe 키,
개인키(PEM), JWT, DB 접속 URI(계정:비밀번호)·JDBC 비번, 하드코딩 비밀번호, 그리고
**국내외 컴플라이언스 중요정보**: 주민등록번호(체크섬 검증)·운전면허·여권번호(개인정보보호법
고유식별정보), 신용카드번호(Luhn 검증, PCI-DSS), US-SSN 등. 패턴은 `rules/secrets_patterns.json`
(데이터 주도, 컴플라이언스 태그 포함). 오탐 억제: 카드/주민번호 유효성 검증 + 플레이스홀더·`process.env`
제외. 탐지값은 **마스킹**해서 표시(평문 노출 방지). 끄기: `SAST_NO_SECRETS=1`, 저위험 패턴(전화/이메일)
켜기: `SAST_SECRETS_ALL=1`.

**교차검증(crossval)**: `--deep` 일 때 패턴 엔진(njsscan)의 오탐을 CodeQL taint 로 정정한다.
예) njsscan 의 `node_nosqli` 는 흐름 분석 없이 패턴만 봐서 Sequelize 파라미터라이즈드 쿼리까지
오탐한다 → 같은 파일에 CodeQL taint 확증이 없으면 `오탐 추정(교차)`으로 강등, 있으면 2엔진 합의(신뢰↑).
룰은 `rules/suppress.json`의 `crossval` 블록(데이터 주도). taint 결과가 없으면(비-deep) 비활성.

또는 Windows에서 `sast-run.bat` 더블클릭 → 대상 입력.

결과: `out/<name>/results.json` + `out/<name>/index.html`(더블클릭, 오프라인).
다른 repo 결과는 `dashboard.template.html`에 `results.json`을 **드래그드롭**해서 봄.

## 계층 (기본 on, 개별 off 가능)

| 계층 | 역할 | 기본 | 끄기 |
|---|---|---|---|
| 1계층 | 룰 스캔 (semgrep·codeql·secrets·sca) | on | 엔진별 `SAST_NO_SECRETS`/`SAST_NO_SCA`, `--deep` 로 codeql |
| 2계층 | 오프라인 트리아지 (suppress·심각도·교차검증) | on | `--no-triage` / `SAST_NO_TRIAGE=1` |
| 3계층 | 동적검증·DAST 브릿지 (라이브 URL) | URL 있을 때 on | `--verify <URL>` 로 켬 / `SAST_NO_VERIFY=1` 로 끔 |

3계층은 라이브 앱 URL 이 있을 때만 켜진다(GET 전용, 안전). 보안헤더 미설정·민감경로 노출(actuator/env·git 등)을
시그니처로 확증하고, 정적 finding 과 라이브 헤더를 **교차연계**(확증/반증)해 `dynamic` 필드를 채운다.
심화 능동 확증(SQLi PoC 재현 등)은 확장 슬롯. LLM 트리아지는 폐쇄망 목표상 기본 미탑재(온라인 옵션 슬롯).

```bash
./sast-run.sh WebGoat/WebGoat --deep --verify http://localhost:8080/WebGoat
```

## 폐쇄망 오프라인 (semgrep 룰 번들)

semgrep 의 `p/…` 레지스트리 팩은 **온라인에서 다운로드**되므로 폐쇄망에서 안 된다.
그래서 룰을 **로컬 번들**에서 로드한다:

```bash
./provision.sh                 # 온라인 머신에서 1회 — 룰 번들 생성(sast/semgrep-rules)
export SAST_SEMGREP_RULES=<번들경로>   # (선택) 번들 위치 지정
```

- 번들 없으면 레지스트리 팩(온라인)으로 자동 폴백. 있으면 오프라인으로 로컬 룰 사용.
- 번들에서 `security`/`secrets`/njsscan 룰만 골라 로드(저신호 룰셋은 제외 — 오탐↓).
- **폐쇄망 반입**: 온라인에서 `./provision.sh` → 툴 전체(+ 번들 디렉터리)를 tar 로 묶어 반입 →
  `SAST_SEMGREP_RULES` 로 가리키면 인터넷 없이 동작. CodeQL/osv-scanner 바이너리·오프라인 DB 도 동일 방식.

## 구조

```
sast/                     코어 (stdlib 전용, 오프라인)
  engines/
    __init__.py           엔진 레지스트리 + run_all (fingerprint 로 dedup 병합)
    semgrep_engine.py     Semgrep 어댑터 (기본, 로컬 룰 번들 → 오프라인)
    secrets_engine.py     중요정보 스캐너 (기본, stdlib 정규식 — 시크릿/개인정보)
    sca_engine.py         SCA (기본, osv-scanner — 의존성 CVE / A06)
    codeql_engine.py      CodeQL 어댑터 (--deep, taint/dataflow)
  rules/
    suppress.json         오탐 억제/심각도/교차검증 룰 라이브러리 (데이터 — 코드 수정 없이 확장)
    secrets_patterns.json 중요정보 탐지 패턴 (데이터 — 컴플라이언스 태그 포함)
  schema.py               통합 finding 스키마 + categorize/fingerprint
  triage.py               2계층: suppress.json 적용(억제 + 심각도, LLM 불필요)
  crossval.py             2계층: 엔진 교차검증(패턴 엔진 오탐을 CodeQL taint 로 정정)
  dynamic.py              3계층: 동적검증/DAST 브릿지(라이브 URL, GET 전용)
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
