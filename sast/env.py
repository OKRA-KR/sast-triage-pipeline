"""실행 환경 판별 + 도구 discovery.

핵심 원칙: **기본은 폐쇄망(offline)** 으로 가정한다 — 명시적으로 켜야 외부통신(2·3계층)이 돈다.
연결성 자동 프로브는 폐쇄망에서 지연/오탐 위험이 있어 기본은 플래그 기반.

- 1계층(룰 스캔 + 오프라인 트리아지): 항상 가능(외부통신 없음).
- 2·3계층(LLM 트리아지/심화): `online` 이고 LLM 설정이 있을 때만.
"""
import os, shutil


def is_online():
    """개방망 여부. 기본 False(폐쇄망 안전). SAST_ONLINE=1 로 켬, SAST_OFFLINE=1 로 강제 끔."""
    if os.environ.get("SAST_OFFLINE"):
        return False
    return bool(os.environ.get("SAST_ONLINE"))


def llm_configured():
    """LLM(원격 키 또는 로컬 엔드포인트)이 설정돼 있는가."""
    return bool(os.environ.get("SAST_LLM_KEY") or os.environ.get("SAST_LLM_ENDPOINT"))


def llm_is_local():
    """로컬 LLM(폐쇄망서도 가능) 여부 — localhost 엔드포인트 + 원격키 없음."""
    ep = os.environ.get("SAST_LLM_ENDPOINT", "")
    return bool(ep) and ("localhost" in ep or "127.0.0.1" in ep) and not os.environ.get("SAST_LLM_KEY")


def layer2_enabled():
    # LLM 만 있으면 됨. 로컬 LLM 이면 폐쇄망서도 가능. 원격 API 는 개방망 전제.
    if os.environ.get("SAST_NO_LLM"):
        return False
    return llm_configured()


def layer3_enabled():
    return layer2_enabled()


def mode_label():
    if llm_is_local():
        return "폐쇄망+로컬LLM"
    if is_online():
        return "개방망(online)"
    return "폐쇄망(offline)"


def tool_path(name, env_var=None, extra_dirs=()):
    """도구 실행파일 위치: 환경변수 → PATH → 추가 후보 경로. 없으면 None.
    (엔진 어댑터의 /home/kali 하드코딩을 대체하는 공통 discovery.)"""
    if env_var:
        v = os.environ.get(env_var)
        if v and os.path.exists(v):
            return v
    w = shutil.which(name)
    if w:
        return w
    cands = list(extra_dirs) + [
        os.path.expanduser(f"~/{name}"),
        os.path.expanduser(f"~/{name}/{name}"),
        os.path.join(os.environ.get("SAST_TOOLS_DIR", ""), name) if os.environ.get("SAST_TOOLS_DIR") else "",
    ]
    for p in cands:
        if p and os.path.exists(p):
            return p
    return None
