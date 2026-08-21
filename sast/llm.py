"""LLM 클라이언트 — 2·3계층용. stdlib urllib 만 사용(zero-dep).

두 포맷 지원:
  - anthropic  : Anthropic Messages API (기본, 원격 API 키)
  - openai     : OpenAI 호환 chat/completions (로컬 LLM — Ollama/vLLM/LM Studio, 사내 게이트웨이)

로컬 LLM 이면 **폐쇄망에서도 2·3계층이 돈다**(외부 인터넷 아님). 미설정/실패 시 None(계층 no-op).

환경변수:
  SAST_LLM_ENDPOINT  엔드포인트 URL (로컬: http://localhost:11434/v1/chat/completions)
  SAST_LLM_MODEL     모델명 (기본 claude-opus-5 / 로컬은 예: qwen2.5:3b)
  SAST_LLM_KEY       API 키 (원격 필요, 로컬은 불필요)
  SAST_LLM_FORMAT    anthropic | openai (미지정 시 엔드포인트로 자동 판별)
  SAST_LLM_VERSION   anthropic-version (기본 2023-06-01)
"""
import json, os, urllib.request, urllib.error

DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-opus-5"


def _endpoint():
    return os.environ.get("SAST_LLM_ENDPOINT", DEFAULT_ENDPOINT)


def _format():
    f = os.environ.get("SAST_LLM_FORMAT")
    if f:
        return f
    ep = _endpoint()
    return "openai" if ("chat/completions" in ep or ":11434" in ep) else "anthropic"


def available():
    # 원격은 키, 로컬은 엔드포인트만 있으면 가능
    return bool(os.environ.get("SAST_LLM_KEY") or os.environ.get("SAST_LLM_ENDPOINT"))


def model():
    return os.environ.get("SAST_LLM_MODEL", DEFAULT_MODEL)


def complete(system, user, max_tokens=4000, timeout=300):
    if not available():
        return None
    endpoint, fmt, key = _endpoint(), _format(), os.environ.get("SAST_LLM_KEY", "")
    if fmt == "openai":
        body = {"model": model(), "max_tokens": max_tokens, "temperature": 0,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        headers = {"content-type": "application/json"}
        if key:
            headers["authorization"] = "Bearer " + key
    else:  # anthropic
        body = {"model": model(), "max_tokens": max_tokens, "system": system,
                "messages": [{"role": "user", "content": user}]}
        headers = {"content-type": "application/json", "x-api-key": key,
                   "anthropic-version": os.environ.get("SAST_LLM_VERSION", "2023-06-01")}
    try:
        req = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"),
                                     headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            doc = json.loads(r.read().decode("utf-8"))
        if fmt == "openai":
            return (doc.get("choices") or [{}])[0].get("message", {}).get("content") or None
        parts = doc.get("content") or []
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text") or None
    except Exception as e:   # 타임아웃/네트워크/파싱 어떤 실패도 계층을 죽이지 않음
        print("[!] LLM 호출 실패:", type(e).__name__, str(e)[:120])
        return None


def complete_json(system, user, max_tokens=4000):
    txt = complete(system, user, max_tokens)
    if not txt:
        return None
    txt = txt.strip()
    if txt.startswith("```"):
        txt = txt.split("```", 2)[1]
        if txt.startswith("json"):
            txt = txt[4:]
    s, e = txt.find("["), txt.rfind("]")
    if s == -1:
        s, e = txt.find("{"), txt.rfind("}")
    try:
        return json.loads(txt[s:e + 1]) if s != -1 else json.loads(txt)
    except ValueError:
        return None
