"""LLM 클라이언트 — 2·3계층(개방망 전용)용. stdlib urllib 만 사용(zero-dep 유지).

기본은 Anthropic Messages API(모델 claude-opus-5). 엔드포인트/모델/키/헤더를 환경변수로
교체 가능 → 사내 게이트웨이·다른 제공자에도 연결. 미설정/실패 시 None 반환(계층 no-op).

  SAST_LLM_KEY       API 키 (필수)
  SAST_LLM_ENDPOINT  기본 https://api.anthropic.com/v1/messages
  SAST_LLM_MODEL     기본 claude-opus-5
  SAST_LLM_VERSION   anthropic-version, 기본 2023-06-01
"""
import json, os, urllib.request, urllib.error

DEFAULT_ENDPOINT = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-opus-5"


def available():
    return bool(os.environ.get("SAST_LLM_KEY"))


def complete(system, user, max_tokens=4000, timeout=90):
    """system+user 프롬프트로 1회 호출 → 응답 텍스트(str) 또는 None."""
    key = os.environ.get("SAST_LLM_KEY")
    if not key:
        return None
    endpoint = os.environ.get("SAST_LLM_ENDPOINT", DEFAULT_ENDPOINT)
    model = os.environ.get("SAST_LLM_MODEL", DEFAULT_MODEL)
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
    }).encode("utf-8")
    headers = {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": os.environ.get("SAST_LLM_VERSION", "2023-06-01"),
    }
    try:
        req = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            doc = json.loads(r.read().decode("utf-8"))
        # Anthropic 응답: content=[{type:text,text:..}]
        parts = doc.get("content") or []
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text") or None
    except (urllib.error.URLError, ValueError, KeyError) as e:
        print("[!] LLM 호출 실패:", str(e)[:120])
        return None


def complete_json(system, user, max_tokens=4000):
    """JSON 응답 기대 → 파싱해서 반환(실패 None). 코드블록/잡음 관대 처리."""
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
