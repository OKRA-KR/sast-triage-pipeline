"""Config — 점검 깊이(축②)·안전레일·전송옵션을 argparse/env 에서 '한 번만' 읽어 담는 타입 객체.

왜: 지금까지 cli.cmd_scan 이 os.environ 을 흐름제어로 set/pop(14곳) 하고, 모드 해석이
_apply_mode 에 흩어져 순서 의존·재진입 위험이 있었다. Config 가 '결정'을 한곳에 모으고,
apply_env() 로 다운스트림 모듈이 읽는 동일 env 를 세팅한다 → 행동은 그대로, 결정은 감사 가능.

이행 원칙(스트랭글러): 아직 env 를 읽는 하위 모듈(replay/okra/login/env.py 등)이 많으므로
apply_env() 는 기존 cli 가 쓰던 것과 '똑같은' env 를 쓴다. 모듈이 Config 를 직접 받도록
옮겨질 때마다 그 env 세팅을 하나씩 걷어낸다.
"""
import os
from dataclasses import dataclass, field


@dataclass
class Config:
    # ── 점검 깊이(축②): 세 모드 중 하나, 아니면 passive ──
    mode: str = "passive"            # "full" | "domain" | "active" | "passive"
    # ── 전송 옵션(인가 대상 전용) ──
    cookie: str | None = None
    headers: list = field(default_factory=list)   # ['Name: Value', ...]
    insecure: bool = False
    oob: bool = False
    # ── 정찰(recon) 플래그 ──
    recon: bool = False
    no_recon: bool = False
    recon_passive: bool = False
    recon_wordlist: str | None = None
    recon_same_port: bool = False
    # ── 출력 ──
    out: str = "out"
    name: str | None = None

    # ── 파생 게이트 ──────────────────────────────────────────────
    @property
    def run_active(self) -> bool:
        """능동 DAST(패킷 전송) 수행 여부 — full/domain/active 에서만."""
        return self.mode in ("full", "domain", "active")

    @property
    def do_recon_default(self) -> bool:
        """--active/--full 은 recon 기본 ON, --domain 은 OFF."""
        return self.mode in ("full", "active")

    # ── 생성: argparse 결과 + 하위호환 env ──────────────────────
    @classmethod
    def from_args(cls, a) -> "Config":
        full = bool(getattr(a, "full", False) or os.environ.get("SAST_FULL"))
        domain = bool(getattr(a, "domain", False))
        active = bool(getattr(a, "active", False) or os.environ.get("SAST_ACTIVE")
                      or os.environ.get("SAST_1LAYER"))
        mode = "full" if full else "domain" if domain else "active" if active else "passive"
        return cls(
            mode=mode,
            cookie=getattr(a, "cookie", None),
            headers=list(getattr(a, "header", []) or []),
            insecure=bool(getattr(a, "insecure", False)),
            oob=bool(getattr(a, "oob", False) or os.environ.get("SAST_OOB")),
            recon=bool(getattr(a, "recon", False)),
            no_recon=bool(getattr(a, "no_recon", False)),
            recon_passive=bool(getattr(a, "recon_passive", False)),
            recon_wordlist=getattr(a, "recon_wordlist", None),
            recon_same_port=bool(getattr(a, "recon_same_port", False)),
            out=getattr(a, "out", "out"),
            name=getattr(a, "name", None),
        )

    # ── 적용: 다운스트림이 읽는 env 를 세팅(행동 보존) ──────────────
    # 원본 cmd_scan 의 출력 순서(전송옵션 배너 → '입력 인식' → 모드 배너)를 지키려
    # 전송옵션과 모드를 분리한다.
    def apply_transport(self):
        """전송 옵션(TLS/쿠키/헤더)을 다운스트림 env 로 브리지."""
        if self.insecure:
            os.environ["SAST_INSECURE_TLS"] = "1"
            print("[!] TLS 인증서 검증 비활성(--insecure) — MITM/위조응답 위험, 인가 폐쇄망 전용")
        if self.cookie:
            os.environ["SAST_HTTP_COOKIE"] = self.cookie
        if self.headers:
            os.environ["SAST_HTTP_HEADERS"] = ";;".join(self.headers)

    def apply_mode(self):
        """점검 깊이(축②)를 다운스트림 env(LLM/recon 게이트)로 브리지 + 배너. run_active 반환."""
        if self.mode == "full":
            os.environ["SAST_ONLINE"] = "1"          # 2·3계층 게이트(LLM 설정 시만 실동작)
            os.environ.pop("SAST_NO_LLM", None)
            from .. import env
            print(f"[*] --full: 능동 DAST(상태변경 포함) + 오프라인 트리아지 + recon + LLM 심화 ({env.mode_label()})")
        elif self.mode == "domain":
            os.environ["SAST_NO_LLM"] = "1"          # 1계층: LLM 강제 OFF
            os.environ["SAST_NO_RECON"] = "1"        # 단일 도메인: 정찰 OFF
            print("[*] --domain: 능동 DAST + 오프라인 트리아지 (단일 도메인 · recon OFF · LLM OFF)")
        elif self.mode == "active":
            os.environ["SAST_NO_LLM"] = "1"          # 1계층: LLM 강제 OFF(폐쇄망 자립)
            print("[*] --active: 능동 DAST + 오프라인 트리아지 + recon (LLM OFF)")
        return self.run_active

    def apply_env(self):
        """전송옵션+모드를 한 번에(테스트/편의용). 반환: run_active."""
        self.apply_transport()
        return self.apply_mode()
