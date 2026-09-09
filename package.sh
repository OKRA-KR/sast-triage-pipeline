#!/usr/bin/env bash
# 반입 tar 생성 — provision.sh 로 tools/ 를 채운 뒤 실행.
# 코드 + 룰데이터 + tools/(엔진·DB·룰번들) 를 하나로 묶는다. 폐쇄망으로 이 파일만 옮기면 됨.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
NAME="sast-kit"
OUT="$ROOT/../$NAME.tar.zst"

if [ ! -d "$ROOT/tools" ]; then
  echo "[!] tools/ 가 없습니다. 먼저 ./provision.sh 를 실행하세요."; exit 1
fi

echo "[*] 패키징 중 … (tools/ 포함, out·targets·.git 제외)"
tar --use-compress-program='zstd -19 -T0' \
    --exclude='./out' --exclude='./targets' --exclude='./.git' \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='_*.py' --exclude='_cmp_*.json' \
    -C "$ROOT/.." -cf "$OUT" "$(basename "$ROOT")"

echo "완료: $OUT  ($(du -h "$OUT" | cut -f1))"
echo
echo "폐쇄망 반입 후:"
echo "  tar --use-compress-program=unzstd -xf $NAME.tar.zst"
echo "  cd $(basename "$ROOT")"
echo "  export SAST_TOOLS_DIR=\$(pwd)/tools     # 엔진·룰·DB 자동 인식"
echo "  export SAST_OSV_OFFLINE=1               # osv 오프라인 DB 사용"
echo "  ./sast-run.sh <대상> [URL] --deep       # 소스+URL 동시(자동판별) · 깊이 --active/--full"
