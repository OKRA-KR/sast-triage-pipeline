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


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tools_dir():
    """반입 키트 도구 루트. SAST_TOOLS_DIR 우선, 없으면 <repo>/tools.
    provision.sh 가 여기에 semgrep-rules/codeql/osv-scanner 등을 모은다 → git+tar 로 반입."""
    return os.environ.get("SAST_TOOLS_DIR") or os.path.join(REPO_ROOT, "tools")


def tool_path(name, env_var=None, extra_dirs=()):
    """도구 실행파일 discovery(이식성): 환경변수 → 반입키트(tools/) → PATH → dev 폴백.
    /home/kali 같은 개발머신 경로는 extra_dirs(최후 폴백)로만."""
    if env_var:
        v = os.environ.get(env_var)
        if v and os.path.isfile(v):
            return v
    td = tools_dir()
    for p in (os.path.join(td, name), os.path.join(td, name, name)):   # flat / nested
        if os.path.isfile(p):
            return p
    w = shutil.which(name)
    if w:
        return w
    for p in extra_dirs:
        if p and os.path.isfile(p):
            return p
    return None
