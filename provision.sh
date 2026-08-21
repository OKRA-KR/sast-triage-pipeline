#!/usr/bin/env bash
# 폐쇄망 반입용 semgrep 룰 번들 프로비저닝 (온라인 머신에서 1회 실행).
#
# 사용:
#   ./provision.sh [번들경로]     # 기본: sast/semgrep-rules
#
# 이후 폐쇄망에서는:
#   - 번들 디렉터리를 툴과 함께 반입
#   - 자동 인식(sast/semgrep-rules) 또는  export SAST_SEMGREP_RULES=<번들경로>
#   → semgrep 이 레지스트리(온라인) 없이 로컬 룰로 동작.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
DEST="${1:-$ROOT/sast/semgrep-rules}"
mkdir -p "$DEST"
echo "[*] 번들 대상: $DEST"

# 1) semgrep-rules — 스캔 언어의 보안 룰만 sparse 로 받는다(용량↓)
if [ ! -d "$DEST/semgrep-rules/.git" ]; then
  echo "[*] semgrep-rules sparse clone…"
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/semgrep/semgrep-rules.git "$DEST/semgrep-rules"
  ( cd "$DEST/semgrep-rules" && \
    git sparse-checkout set java javascript typescript python generic yaml terraform dockerfile html )
else
  echo "[*] semgrep-rules 이미 있음 — pull"; ( cd "$DEST/semgrep-rules" && git pull --quiet || true )
fi

# 2) njsscan 의 semgrep(semantic_grep) 룰 — Node 전용 보안룰(NoSQL 등)
if [ ! -d "$DEST/njsscan/.git" ]; then
  echo "[*] njsscan clone…"
  git clone --depth 1 https://github.com/ajinabraham/njsscan.git "$DEST/njsscan"
else
  echo "[*] njsscan 이미 있음 — pull"; ( cd "$DEST/njsscan" && git pull --quiet || true )
fi

SEC=$(find "$DEST" -type d \( -name security -o -name secrets -o -name semantic_grep \) | wc -l)
echo
echo "완료. 보안 룰 디렉터리 $SEC 개."
echo "폐쇄망 반입: '$DEST' 를 툴과 함께 옮기고, 필요시  export SAST_SEMGREP_RULES=$DEST"
