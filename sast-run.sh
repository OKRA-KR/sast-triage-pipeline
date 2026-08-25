#!/usr/bin/env bash
# 실행형 SAST 러너 (repo 무관). 실행자가 직접 트리거한다. AI 불필요.
#
# 사용:
#   ./sast-run.sh <대상>
#     <대상> = 로컬경로 | git URL | owner/repo | targets/ 아래 폴더명
#
# 예:
#   ./sast-run.sh /home/kali/juice-shop
#   ./sast-run.sh https://github.com/juice-shop/juice-shop.git
#   ./sast-run.sh juice-shop/juice-shop
#   ./sast-run.sh myproject          # targets/myproject 를 스캔
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGETS="$ROOT/targets"; OUTBASE="$ROOT/out"
mkdir -p "$TARGETS" "$OUTBASE"

ARG=""; DEEP=""; VERIFY=""; ONLINE=""; ACTIVE=""; COOKIE=""; OKRA=""; CAPTURE=""
# 옵션 파싱: --deep, --online, --active, --verify <URL>, --cookie <쿠키>, --capture <파일>
prev=""
for a in "$@"; do
  if [ "$prev" = "--verify" ]; then VERIFY="$a"; prev=""; continue; fi
  if [ "$prev" = "--cookie" ]; then COOKIE="$a"; prev=""; continue; fi
  if [ "$prev" = "--capture" ]; then CAPTURE="$a"; prev=""; continue; fi
  case "$a" in
    --deep) DEEP=1 ;;
    --online) ONLINE=1 ;;
    --active) ACTIVE=1 ;;
    --okra|--zap) OKRA=1 ;;
    --verify) prev="--verify" ;;
    --cookie) prev="--cookie" ;;
    --capture) prev="--capture" ;;
    *) [ -z "$ARG" ] && ARG="$a" ;;
  esac
done
# 대상(소스) 없이 --verify/--capture 만 있으면 URL 전용/패시브 모드
if [ -z "$ARG" ] && [ -z "$VERIFY" ] && [ -z "$CAPTURE" ]; then
  echo "사용법: ./sast-run.sh <경로|gitURL|owner/repo|폴더명> [--deep] [--online] [--verify <URL> [--active]]"
  echo "   또는: ./sast-run.sh --verify <URL> [--active]        # 소스 없이 URL 점검"
  echo "   또는: ./sast-run.sh --capture <Burp/HAR> [--active]  # 캡처 패시브 분석(패킷0)"
  exit 1
fi
if [ -z "$ARG" ]; then
  if [ -n "$VERIFY" ]; then
    NAME="$(echo "$VERIFY" | sed -E 's#https?://##; s#[:/].*##')"; EXTRA="--verify $VERIFY"
    echo "[*] URL 전용 점검: $VERIFY"
  else
    NAME="$(basename "$CAPTURE" | sed -E 's#\.[^.]+$##')"; EXTRA="--capture $CAPTURE"
    echo "[*] 패시브 캡처 분석(패킷0): $CAPTURE"
  fi
  OUT="$OUTBASE/$NAME"
  [ -n "$CAPTURE" ] && [ -n "$VERIFY" ] && EXTRA="$EXTRA --capture $CAPTURE"
  [ -n "$ACTIVE" ] && EXTRA="$EXTRA --active" && echo "[!] 능동 DAST — 인가 대상 전용"
  [ -n "$OKRA" ] && EXTRA="$EXTRA --okra" && echo "[!] OKRA DAST — 인가 대상 전용"
  [ -n "$COOKIE" ] && export SAST_HTTP_COOKIE="$COOKIE" && echo "[*] 세션 쿠키 주입됨"
  echo "[*] 출력: $OUT"
  ( cd "$ROOT" && python3 -m sast scan --out "$OUT" --name "$NAME" $EXTRA )
  echo "완료: $OUT/index.html  (엔드포인트: $OUT/endpoints.csv)"; exit 0
fi
if [ -n "$DEEP" ]; then export SAST_DEEP=1 SAST_CODEQL_CACHE=1; echo "[*] deep 모드: CodeQL(taint) 포함"; fi

# 대상 해석 -> 로컬 경로 TARGET + 이름 NAME
if [ -d "$ARG" ]; then
  TARGET="$(cd "$ARG" && pwd)"; NAME="$(basename "$TARGET")"
elif [ -d "$TARGETS/$ARG" ]; then
  TARGET="$TARGETS/$ARG"; NAME="$ARG"
else
  # URL 또는 owner/repo → clone
  case "$ARG" in
    http*://*|git@*) URL="$ARG" ;;
    */*)             URL="https://github.com/$ARG.git" ;;
    *) echo "대상을 찾을 수 없음: $ARG (경로/URL/owner-repo/폴더명)"; exit 1 ;;
  esac
  NAME="$(basename "${URL%.git}")"
  TARGET="$TARGETS/$NAME"
  if [ -d "$TARGET/.git" ]; then
    echo "[*] 기존 클론 갱신: $NAME"; git -C "$TARGET" pull --quiet || true
  else
    echo "[*] 클론: $URL"; git clone --depth 1 "$URL" "$TARGET"
  fi
fi

OUT="$OUTBASE/$NAME"
echo "[*] 대상: $TARGET"
echo "[*] 출력: $OUT"
EXTRA=""
[ -n "$VERIFY" ] && EXTRA="$EXTRA --verify $VERIFY" && echo "[*] 블랙박스 점검 대상: $VERIFY"
[ -n "$CAPTURE" ] && EXTRA="$EXTRA --capture $CAPTURE" && echo "[*] 패시브 캡처 분석: $CAPTURE"
[ -n "$ACTIVE" ] && EXTRA="$EXTRA --active" && echo "[!] 능동 DAST — 인가 대상 전용"
[ -n "$OKRA" ] && EXTRA="$EXTRA --okra" && echo "[!] OKRA DAST — 인가 대상 전용"
[ -n "$COOKIE" ] && export SAST_HTTP_COOKIE="$COOKIE" && echo "[*] 세션 쿠키 주입됨"
[ -n "$ONLINE" ] && EXTRA="$EXTRA --online" && echo "[*] 개방망 모드: 2·3계층(LLM) 활성화 시도"
( cd "$ROOT" && python3 -m sast scan "$TARGET" --out "$OUT" --name "$NAME" $EXTRA )

echo
echo "완료. 대시보드를 브라우저로 여세요:"
# WSL 경로를 Windows 경로로 안내
WINPATH="$(echo "$OUT/index.html" | sed 's#^/mnt/\([a-z]\)/#\U\1:/#')"
echo "  $WINPATH"
echo "  (또는 out/$NAME/results.json 을 dashboard.template.html 에 드래그드롭)"
