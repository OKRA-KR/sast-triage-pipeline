# SAST+DAST — repo-무관 계층형 스캐너 (폐쇄망 우선)

**여러 현장(인가/폐쇄 환경)에 반입해 쓰는 범용 도구.** 소스를 떨어뜨리면 SAST, 라이브 URL 을 주면 블랙박스.

## 아키텍처 (2 트랙 · 3 계층)

```
Track A (Repo 있음)  → SAST
  1계층 [오프라인·폐쇄망 baseline]  룰 4엔진(semgrep·secrets·sca·codeql) + 오프라인 트리아지(suppress/crossval)
  2계층 [개방망 전용·외부통신]      LLM 트리아지 — 오탐/정탐 판별·근거
  3계층 [개방망 전용·외부통신]      LLM 심화 — 공격구문(PoC)·공격포인트·조치 생성
Track B (Repo 없음)  → 블랙박스     라이브 URL 엔드포인트 식별 → 공격 가능 포인트 (stdlib, LLM 불필요)
Track C (캡처 파일)  → 패시브 분석  Burp/HAR 오프라인 파싱 → 엔드포인트 인벤토리(CSV)+취약점 (패킷0)
```

**환경 게이팅**: 기본 **폐쇄망(offline)** → 1계층만(외부통신 0). `--online`(또는 `SAST_ONLINE=1`) +
LLM 설정(`SAST_LLM_KEY`)이 있을 때만 2·3계층이 켜진다. 폐쇄망에선 LLM 계층이 아예 실행되지 않음.

```bash
./sast-run.sh <대상>                         # 폐쇄망: 1계층만
./sast-run.sh <대상> --deep                  # + CodeQL taint
./sast-run.sh <대상> --deep --verify <URL>   # + 블랙박스(라이브 수동 점검)
./sast-run.sh <대상> --deep --online         # 개방망: 2·3계층(LLM) 활성화 (SAST_LLM_KEY 필요)
./sast-run.sh --verify <URL>                 # 소스 없이 URL 전용 점검(블랙박스)
./sast-run.sh --verify <URL> --active        # URL 능동 DAST (인가 대상 전용, payload 주입)
./sast-run.sh --verify <URL> --active --cookie 'PHPSESSID=..'   # 세션 쿠키로 인증된 상태 점검
./sast-run.sh --verify <URL> --okra --cookie 'PHPSESSID=..'     # OKRA DAST(엔진 OWASP ZAP: spider+AJAX+active scan + 중요정보 스캔)
./sast-run.sh --capture capture.xml                            # 패시브: Burp/HAR 오프라인 분석 → endpoints.csv + 취약점(패킷0)
./sast-run.sh --capture capture.xml --active                   # + 식별된 엔드포인트 정밀 능동 점검(인가 전용, 패킷 전송)
#   <대상> = 로컬경로 | git URL | owner/repo | targets/ 폴더명   (대상 생략 + --verify/--capture = 소스 없이 점검)
```

LLM 계층 설정: `SAST_LLM_KEY`(필수), `SAST_LLM_ENDPOINT`(기본 Anthropic), `SAST_LLM_MODEL`(기본 claude-opus-5).
엔드포인트/모델 교체로 사내 게이트웨이·다른 제공자 연결. stdlib urllib 만 사용(zero-dep 유지).

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

## 계층·트랙 요약

| 구분 | 역할 | 외부통신 | 기본 | 켜기/끄기 |
|---|---|---|---|---|
| **1계층** | 룰 4엔진 + 오프라인 트리아지(suppress/crossval) | ✗ (폐쇄망 OK) | on | 엔진별 `SAST_NO_*`, `--deep`(codeql), `--no-triage` |
| **2계층** | LLM 트리아지 (오탐/정탐 판별) | ✓ | off | `--online` + `SAST_LLM_KEY` |
| **3계층** | LLM 심화 (PoC/공격포인트/조치) | ✓ | off | `--online` + `SAST_LLM_KEY` |
| **블랙박스**(Track B) | 라이브 URL 엔드포인트→공격포인트(수동 recon) | ✗ (내부망) | URL 있을 때 | `--verify <URL>` / `SAST_NO_VERIFY=1` |
| **능동 DAST**(Track B) | URL 크롤→파라미터에 탐지 payload 주입(SQLi/XSS/SSTI/경로/리다이렉트) | ✗ (내부망) | off | `--active` (**인가 대상 전용**) |
| **OKRA DAST**(Track B) | OWASP ZAP 엔진(spider+AJAX+active scan) + **응답 본문 중요정보(주민번호·카드·토큰) 스캔** | ✗ (내부망, ZAP 반입) | off | `--okra` (**인가 대상 전용**) |
| **패시브 분석**(Track C) | 캡처(Burp/HAR) 오프라인 파싱 → 엔드포인트 인벤토리(CSV) + 보안헤더·쿠키플래그·응답 중요정보·URL 자격증명·verbose오류·CORS·계정열거·IDOR후보·CSRF부재 | ✓ (**패킷 0**) | off | `--capture <파일>` |
| **↳ 타깃 능동**(Track C) | 식별한 엔드포인트/파라미터에만 payload 정밀 주입(blind 크롤 대신) | ✗ (내부망) | off | `--capture <파일> --active` (**인가 전용**) |

- **OKRA DAST**: 성숙한 스캔 엔진으로 [OWASP ZAP](https://www.zaproxy.org/)(Apache-2.0)을 구동하고, alert 를 유형별로 집계·정규화한 뒤 **ZAP 이 못 하는 국내 컴플라이언스 중요정보**(주민번호 체크섬·카드 Luhn·PAT·DB 자격증명)를 라이브 응답 본문에서 추가 탐지한다(OKRA 1계층 secrets 엔진 재사용). ZAP 은 오프라인 Java 앱이라 폐쇄망 반입 가능. 엔진 크레딧: OWASP ZAP.
- **패시브 분석(Track C)**: 현장에서 프록시로 **이미 확보한 캡처**(Burp items XML / HAR)를 오프라인 파싱해 **패킷 한 개도 안 쏘고** ① 대상 엔드포인트 전체를 식별(메서드·경로·파라미터·인증여부·상태변경) → `endpoints.csv`, ② 실제 요청/응답에서 관측되는 취약점을 룰로 탐지한다. 크롤러가 못 찾는 POST API·JS 뒤 파라미터까지 잡히므로, 이 인벤토리를 `--active` 로 그대로 **정밀 능동 점검**(식별된 파라미터에만 payload 주입 → blind 크롤 대비 정밀도↑·요청수↓)에 넘길 수 있다. 사내 스캐너 트래픽 제약이 있는 폐쇄망에서 캡처만으로 1계층을 돌리는 핵심 경로.
- **폐쇄망**: 기본값이 offline 이라 2·3계층이 실행조차 안 됨 → 1계층(+선택 블랙박스)만.
- **개방망**: `--online` + LLM 키가 있어야 2·3계층이 돈다. 하나라도 없으면 자동 건너뜀(안전).
- 블랙박스는 LLM 불필요 — 소스가 없거나(Track B) SAST 와 병행해 라이브 확증에 쓴다(GET 전용, 시그니처로 오탐 억제).

```bash
# 폐쇄망 SAST + 라이브 블랙박스
./sast-run.sh WebGoat/WebGoat --deep --verify http://localhost:8080/WebGoat
# 개방망 SAST 1~3계층
SAST_LLM_KEY=... ./sast-run.sh WebGoat/WebGoat --deep --online
```

## 이식성 & 폐쇄망 반입 (carry-in kit)

**여러 현장에 git clone → tar 로 반입**하는 모델. 모든 무거운 의존성을 repo-내 `tools/` 한 곳에
모아 통째로 옮긴다. 엔진은 `SAST_TOOLS_DIR`(기본 `<repo>/tools`)에서 자동 탐색 —
특정 머신 경로(`/home/kali` 등)에 묶이지 않음(그건 개발용 최후 폴백).

```bash
# ── 온라인 머신에서 (1회) ──
git clone <repo> && cd sast-draft
./provision.sh              # tools/ 에 수집: semgrep 룰 + osv(바이너리+오프라인DB) + CodeQL 번들
./provision.sh --with-llm   # + Ollama + 로컬 모델(2·3계층 오프라인용, 용량 큼)
./package.sh                # → ../sast-kit.tar.zst (tools/ 포함)

# ── 폐쇄망에서 ──
tar --use-compress-program=unzstd -xf sast-kit.tar.zst && cd sast-draft
export SAST_TOOLS_DIR=$(pwd)/tools     # 엔진·룰·DB 자동 인식
export SAST_OSV_OFFLINE=1               # osv 오프라인 DB 사용(tools/osv-cache)
./sast-run.sh <대상> --deep [--verify <URL>]
```

반입 키트 구성(`tools/`): `semgrep-rules/`(security 룰만), `osv-scanner`+`osv-cache/`(오프라인 CVE DB),
`codeql/`(CLI+쿼리팩), (선택) `ollama/`+`ollama-models/`. semgrep 은 `p/…` 레지스트리(온라인) 대신
이 로컬 번들을 로드하고, 번들 없으면 레지스트리로 폴백한다. CodeQL 은 쿼리팩까지 있어야 오프라인 동작(번들 사용).

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
    attack_playbook.json  카테고리별 공격구문/조치 (데이터 — ctf-web 스킬에서 증류)
  schema.py               통합 finding 스키마 + categorize/group/fingerprint
  env.py                  환경 판별(폐쇄망/개방망) + 도구 discovery
  triage.py               1계층: suppress.json 적용(억제 + 심각도, 오프라인)
  crossval.py             1계층: 엔진 교차검증(패턴 엔진 오탐을 CodeQL taint 로 정정)
  playbook.py             1계층: 공격 플레이북 enrichment(카테고리별 공격구문/조치, 오프라인)
  llm.py                  LLM 클라이언트(stdlib urllib, Anthropic 기본, 교체 가능)
  layer2.py               2계층: LLM 트리아지 (개방망 전용)
  layer3.py               3계층: LLM 심화 — PoC/공격포인트/조치 (개방망 전용)
  blackbox.py             Track B: 라이브 URL 엔드포인트→공격포인트, 수동 recon (LLM 불필요)
  active.py               Track B 경량 능동 DAST: 크롤+payload 주입 (--active, 의존성0)
  okra.py                 Track B OKRA DAST: OWASP ZAP(Apache-2.0) 구동+alert 정규화 + 응답 본문 중요정보 스캔 (--okra)
  capture.py              Track C 패시브 분석: Burp/HAR 파싱→엔드포인트 인벤토리(CSV)+오프라인 룰 (--capture, 패킷0)
  report.py               results.json(sast-results/2) + 대시보드 생성
  cli.py                  python3 -m sast scan <target> --out <dir> [--online] [--verify URL]
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
