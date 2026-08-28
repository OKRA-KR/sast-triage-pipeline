#!/usr/bin/env bash
# OKRA 통합 러너 — 인자 자동판별(폴더=소스 · http(s)=URL · 파일=캡처). 실행자가 직접 트리거.
# 여러 대상을 한 번에: 소스+URL+캡처를 같이 주면 통합 스캔 + 상관분석까지 한 번에.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGETS="$ROOT/targets"; OUTBASE="$ROOT/out"
mkdir -p "$TARGETS" "$OUTBASE"

if [ "$#" -eq 0 ]; then
  cat <<'USAGE'
사용법: ./sast-run.sh <대상> [<대상> ...] [옵션]
  대상(자동판별): 폴더(소스) | http(s)://URL | Burp/HAR 캡처파일 | gitURL(.git) | owner/repo | targets/폴더명
  옵션: --deep(CodeQL taint)  --online(LLM 2·3계층)  --active / --okra(능동 DAST, 인가전용)
        --recon(하위도메인 열거→라이브 호스트까지 원스텝)  --recon-passive(crt.sh)  --recon-same-port
        --cookie 'PHPSESSID=..'  --insecure(TLS검증끔)  --no-triage
예:
  ./sast-run.sh ./myapp                              # 소스 SAST
  ./sast-run.sh https://app.example.com             # URL 점검(안전 recon)
  ./sast-run.sh gparking2                            # 캡처 패시브(패킷0)
  ./sast-run.sh ./myapp https://app.com cap.har      # 동시 + 상관분석
  ./sast-run.sh gparking2 --active --cookie 'PHPSESSID=..'   # 능동(인가 대상 전용)
USAGE
  exit 1
fi

RESOLVED=(); PASS=(); NAME=""; prev=""
clone() {  # $1=git URL, $2=name → targets/$2 로 clone/갱신, RESOLVED 에 경로 추가
  local url="$1" n="$2" t="$TARGETS/$2"
  if [ -d "$t/.git" ]; then echo "[*] 클론 갱신: $n"; git -C "$t" pull --quiet || true
  else echo "[*] 클론: $url"; git clone --depth 1 "$url" "$t"; fi
  RESOLVED+=("$t"); [ -z "$NAME" ] && NAME="$n"
}

for a in "$@"; do
  if [ -n "$prev" ]; then PASS+=("$a"); prev=""; continue; fi   # 값 받는 플래그의 값
  case "$a" in
    --deep) export SAST_DEEP=1 SAST_CODEQL_CACHE=1; echo "[*] deep: CodeQL(taint) 포함"; continue ;;
    -H|--verify|--capture|--cookie|--header|--name|--recon-wordlist) PASS+=("$a"); prev="$a"; continue ;;
    --*|-*) PASS+=("$a"); continue ;;
  esac
  # positional 대상 해석 (clone 만 여기서, 나머지 판별은 CLI 가 자동)
  if [ -d "$a" ]; then
    RESOLVED+=("$(cd "$a" && pwd)"); [ -z "$NAME" ] && NAME="$(basename "$a")"
  elif [ -d "$TARGETS/$a" ]; then
    RESOLVED+=("$TARGETS/$a"); [ -z "$NAME" ] && NAME="$a"
  elif { [ "${a%.git}" != "$a" ] && [ "${a#http}" != "$a" ]; } || [ "${a#git@}" != "$a" ]; then
    clone "$a" "$(basename "${a%.git}")"                       # gitURL(.git) / git@ → clone
  elif [ "${a#http}" != "$a" ]; then
    RESOLVED+=("$a"); [ -z "$NAME" ] && NAME="$(echo "$a" | sed -E 's#https?://##; s#[:/].*##')"  # 라이브 URL
  elif [ -f "$a" ]; then
    RESOLVED+=("$a"); [ -z "$NAME" ] && NAME="$(basename "$a" | sed -E 's#\.[^.]+$##')"           # 캡처
  elif [ "${a#*/}" != "$a" ]; then
    clone "https://github.com/$a.git" "$(basename "$a")"       # owner/repo → github
  else
    echo "대상 해석 실패: $a (폴더/URL/파일/gitURL/owner-repo)"; exit 1
  fi
done

[ -z "$NAME" ] && NAME="scan"
OUT="$OUTBASE/$NAME"
echo "[*] 대상: ${RESOLVED[*]:-(없음)}"
echo "[*] 출력: $OUT"
( cd "$ROOT" && python3 -m sast scan "${RESOLVED[@]}" --out "$OUT" --name "$NAME" ${PASS[@]+"${PASS[@]}"} )

echo
WINPATH="$(echo "$OUT/index.html" | sed 's#^/mnt/\([a-z]\)/#\U\1:/#')"
echo "완료: $WINPATH"
[ -f "$OUT/endpoints.csv" ] && echo "엔드포인트: $OUT/endpoints.csv"
