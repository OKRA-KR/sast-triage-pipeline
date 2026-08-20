# SAST 엔진 개선 인풋 (오탐/미탐 분석)

> 이 문서는 **대시보드에 노출하지 않는다.** 목적은 오탐률 감소 — 오탐 패턴을 룰로 학습(트리아지 FP-role)하고 1계층(Semgrep) 스캔을 손보는 데 쓴다.
> 근거: 라이브 인스턴스 능동 점검(`dast_probe.py`) + 동적 검증(`verify.py`) 결과.

## 1. 오탐률 현황

| 구분 | 건수 | 비고 |
|---|---|---|
| Semgrep 원시 탐지 | 43 | 1계층 출력 |
| 동적 확증(실제 재현) | 9 | 대시보드에 노출되는 최종 결과 |
| **오탐·비적용(억제 대상)** | **13** | 아래 2절 — 실제 위험 아님 |
| 저위험 하드닝(CI/IaC, 별도 트랙) | 21 | 진짜지만 앱 런타임 위험 아님 |

**오탐률(위험 아닌데 올라온 비율) ≈ 13/43 = 30%.** 억제 룰 적용 시 이 13건은 1계층/2계층에서 사라진다.

## 2. 오탐 목록과 근거 (동적으로 확인)

| finding | 클래스 | 왜 오탐인가 (증거) |
|---|---|---|
| F015 F016 F023 F024 | SQL 인젝션 | `data/static/codefixes/*` = 챌린지 훈련 스니펫. 마운트된 라우트 아님. 능동 점검에서 해당 경로는 정적 파일로만 제공되고 SQL 주입 엔드포인트가 아님. 실주입은 라이브 라우트 F035뿐. |
| F030 F031 F033 | 경로 순회 | `!file.includes('/')` 가드가 앞에 있어 `../` 이탈 차단. `GET /encryptionkeys/%2e%2e%2fpackage.json` → **HTTP 403**. 재현 불가. |
| F017 F019 F021 F026 F042 | IaC 오설정 | `"public"` 이름의 서브넷에 공인 IP 부여 — ALB/NAT용 퍼블릭 서브넷은 설계상 정상. 문맥 없는 일반 룰의 오탐. |
| F022 | IaC(TLS) | `*_correct.tf` = 챌린지 '정답' 참조 파일. 정답인데도 걸림. |

## 3. 오탐 억제 룰 (트리아지 FP-role 학습)

2계층 트리아지가 **자동으로 FALSE_POSITIVE 처리**할 패턴:

1. **fixture/정답 파일**: 경로가 `**/codefixes/**` 또는 파일명이 `*_correct.*` → `verdict=FALSE_POSITIVE (fixture)`.
2. **비-라우트 싱크**: injection 계열인데 해당 파일에 Express 핸들러(`app.(get|post|use)`)로 연결된 흔적이 없으면 → `reachable=false` → 런타임 위험에서 제외.
3. **가드 선행 경로순회**: `sendFile`/파일 접근 앞에 같은 핸들러 안에서 `!x.includes('/')` 또는 정규화+접두검증이 있으면 → 강등(FALSE_POSITIVE 또는 최저순위).
4. **의도적 퍼블릭 IaC**: `aws_subnet "public"` + `map_public_ip_on_launch=true` → 정보성(억제). 진짜 문제는 `"private"` 서브넷에 공인 IP가 붙은 경우만.
5. **트랙 분리**: IaC/CI(GitHub Actions) 계열은 앱 취약점 대시보드가 아니라 **하드닝 트랙**으로 라우팅.

## 4. 1계층(Semgrep) 개선

```bash
# 챌린지 fixture 디렉터리 스캔 제외 (오탐 F015/F016/F023/F024 제거)
semgrep scan ... --exclude 'data/static/codefixes' --exclude '*_correct.*'

# IaC/CI 는 앱 코드 스캔과 분리해서 별도 패스로
semgrep scan --config p/terraform --config p/github-actions <infra 경로만>
```

- `express-sequelize-injection` 룰에 **taint 소스 확인** 추가 — `req.*` 오염이 실제로 싱크까지 흐를 때만. codefix 스니펫처럼 라우트 밖 함수는 제외.
- 경로순회 룰: 같은 함수 스코프에 슬래시 차단 가드가 있으면 downgrade하는 rule 조합(Semgrep `patterns` + `pattern-not`).

## 5. 미탐(FN) 갭 — SAST가 구조적으로 못 보는 것

능동 점검이 찾았지만 Semgrep이 놓친 클래스. **1계층만으론 안 되고 계층 추가가 필요**:

| 미탐 | 왜 SAST가 못 보나 | 보강 방법 |
|---|---|---|
| 장바구니 IDOR / 접근제어 | 소유권 검사 부재는 데이터 흐름이 아니라 **인가 로직**. 정적으로 추론 불가 | 인증 DAST(ZAP/nuclei auth), 오브젝트 소유권 테스트 |
| 전체 사용자 열거 | 엔드포인트가 '동작'은 정상. 권한 범위가 문제 | 라우트 인벤토리 + 권한 매트릭스 점검 |
| /metrics·/api-docs 노출 | 마운트는 정상 코드. '무인증 노출'이 문제 | 라우트 인벤토리 룰(민감 엔드포인트 무인증 마운트 탐지) + 콘텐츠 디스커버리 |
| 보안 헤더 누락 | 없는 것을 정적으로 잡기 어려움 | helmet 설정 유무 체크 + DAST 헤더 스캔 |
| 로그인 무차별 방어 부재 | 부재의 증명 | rate-limit 미들웨어 설정 점검 + 런타임 테스트 |

→ 결론: **오탐은 2계층 FP-role + 1계층 exclude로 줄이고, 미탐은 DAST/런타임 점검을 3계층으로 상시화**한다. 이번 파이프라인의 `dast_probe.py`가 그 3계층 시드다.
