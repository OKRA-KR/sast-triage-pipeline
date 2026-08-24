#!/usr/bin/env bash
# 반입 키트 프로비저닝 — 온라인 머신에서 1회 실행.
# 모든 오프라인 의존성을 <repo>/tools/ 에 모은다 → git+tar 로 폐쇄망 반입.
#
# 사용:
#   ./provision.sh                 # semgrep 룰 + osv(바이너리+DB) + codeql 번들
#   ./provision.sh --with-llm      # + Ollama + 로컬 모델(용량 큼)
#   TOOLS=/경로 ./provision.sh     # tools 위치 지정(기본 <repo>/tools)
#
# 반입: ./package.sh 로 tar 생성 → 폐쇄망에서 풀고  export SAST_TOOLS_DIR=<repo>/tools
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOLS="${TOOLS:-$ROOT/tools}"
WITH_LLM=""; for a in "$@"; do [ "$a" = "--with-llm" ] && WITH_LLM=1; done
mkdir -p "$TOOLS"
echo "[*] 반입 키트 위치: $TOOLS"
ok(){ echo "  ✓ $1"; }; warn(){ echo "  ! $1"; }

# 1) semgrep 룰 (security 하위만 sparse)
if [ ! -d "$TOOLS/semgrep-rules/semgrep-rules" ]; then
  echo "[*] semgrep-rules …"
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/semgrep/semgrep-rules.git "$TOOLS/semgrep-rules/semgrep-rules" 2>/dev/null \
    && ( cd "$TOOLS/semgrep-rules/semgrep-rules" && git sparse-checkout set java javascript typescript python generic yaml terraform dockerfile html ) \
    && git clone --depth 1 https://github.com/ajinabraham/njsscan.git "$TOOLS/semgrep-rules/njsscan" 2>/dev/null \
    && ok "semgrep-rules + njsscan" || warn "semgrep-rules 실패"
else ok "semgrep-rules (이미 있음)"; fi

# 2) osv-scanner 바이너리 + 오프라인 OSV DB
if [ ! -x "$TOOLS/osv-scanner" ]; then
  echo "[*] osv-scanner …"
  url=$(curl -s https://api.github.com/repos/google/osv-scanner/releases/latest \
        | grep -oE "https://[^\"]*osv-scanner_linux_amd64" | head -1)
  [ -n "$url" ] && curl -sL "$url" -o "$TOOLS/osv-scanner" && chmod +x "$TOOLS/osv-scanner" && ok "osv-scanner" || warn "osv-scanner 실패"
else ok "osv-scanner (이미 있음)"; fi
if [ -x "$TOOLS/osv-scanner" ]; then
  echo "[*] OSV 오프라인 DB 다운로드 …"
  mkdir -p "$TOOLS/osv-cache" /tmp/_osvseed
  printf 'requests==2.0.0\n' > /tmp/_osvseed/requirements.txt
  XDG_CACHE_HOME="$TOOLS/osv-cache" "$TOOLS/osv-scanner" scan source \
    --offline-vulnerabilities --download-offline-databases \
    -L /tmp/_osvseed/requirements.txt >/dev/null 2>&1
  [ -d "$TOOLS/osv-cache/osv-scanner" ] && ok "OSV DB → tools/osv-cache" || warn "OSV DB 다운로드 확인 필요"
fi

# 3) CodeQL 번들(CLI + 쿼리팩 — 오프라인 필수)
if [ ! -x "$TOOLS/codeql/codeql" ]; then
  echo "[*] CodeQL 번들 …(수백 MB)"
  curl -sL "https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz" \
    -o /tmp/_cqbundle.tgz \
    && tar -xzf /tmp/_cqbundle.tgz -C "$TOOLS" && rm -f /tmp/_cqbundle.tgz \
    && ok "codeql 번들 → tools/codeql" || warn "codeql 실패"
else ok "codeql (이미 있음)"; fi

# 4) (선택) 로컬 LLM: Ollama + 소형 모델
if [ -n "$WITH_LLM" ]; then
  echo "[*] Ollama + 모델 …(용량 큼)"
  if [ ! -x "$TOOLS/ollama/bin/ollama" ]; then
    ourl=$(curl -s https://api.github.com/repos/ollama/ollama/releases/latest \
          | grep -oE "https://[^\"]*ollama-linux-amd64.tar.zst" | grep -v mlx | head -1)
    mkdir -p "$TOOLS/ollama" && curl -sL "$ourl" -o /tmp/_oll.zst \
      && tar --use-compress-program=unzstd -xf /tmp/_oll.zst -C "$TOOLS/ollama" && rm -f /tmp/_oll.zst && ok "ollama" || warn "ollama 실패"
  fi
  OLLAMA_MODELS="$TOOLS/ollama-models" LD_LIBRARY_PATH="$TOOLS/ollama/lib" \
    "$TOOLS/ollama/bin/ollama" serve >/tmp/_oll.log 2>&1 &
  sleep 5
  OLLAMA_MODELS="$TOOLS/ollama-models" LD_LIBRARY_PATH="$TOOLS/ollama/lib" \
    "$TOOLS/ollama/bin/ollama" pull "${SAST_LLM_MODEL:-qwen2.5:3b}" && ok "모델 → tools/ollama-models" || warn "모델 pull 실패"
fi

echo
echo "완료. 반입: ./package.sh  →  sast-kit.tar.zst 를 폐쇄망으로."
echo "폐쇄망에서: tar 풀고  export SAST_TOOLS_DIR=$TOOLS  (엔진이 자동 인식)"
