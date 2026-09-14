"""ScanContext — 한 번의 scan 이 나르는 모든 상태를 담는 객체.

지금까지 cmd_scan 의 지역변수(findings/endpoints_all/exs/layers…)로 손스레딩되던 것을
한 객체로 모은다. 스테이지는 ctx 를 받아 자기 자리(surface/findings/layers)에 append 한다.
스트랭글러 이행 중: cmd_scan 이 이 객체를 만들어 채우고, 스테이지가 하나씩 이사 온다.
"""
import os
from dataclasses import dataclass, field
from .config import Config


def resolve_name(repo, verify, cap, override=None):
    """표시 이름 결정: override(--name) > 폴더명 > 호스트 > 캡처파일명 > 'scan'."""
    if override:
        return override
    if repo:
        return os.path.basename(repo.rstrip("/\\"))
    if verify:
        return verify.split("//")[-1].split("/")[0]
    if cap:
        return os.path.splitext(os.path.basename(cap))[0]
    return "scan"


@dataclass
class ScanContext:
    config: Config

    # ── 입력(축①): 자동판별 결과 ──────────────────────────────
    repo: str | None = None          # 소스 폴더(SAST)
    verify_url: str | None = None    # 라이브 URL(DAST)
    capture: str | None = None       # 캡처 파일(패시브)

    # ── 표면(surface): 엔드포인트/정찰 인벤토리 ──────────────
    endpoints: list = field(default_factory=list)   # 엔드포인트 인벤토리(캡처/크롤/recon/wayback 합류)
    recon_subs: dict = field(default_factory=dict)   # 정찰 해석 서브도메인
    recon_live: list = field(default_factory=list)   # 라이브 하위도메인

    # ── 분석 산출 ─────────────────────────────────────────────
    findings: list = field(default_factory=list)
    engines: list = field(default_factory=list)
    layers: list = field(default_factory=list)       # 실행 계보(리포트 mode 문자열)
    exs: list | None = None                           # 캡처/크롤 교환(exchanges)
    oob_listener: object = None

    @property
    def have_repo(self) -> bool:
        return bool(self.repo and os.path.isdir(self.repo))

    @property
    def name(self) -> str:
        return resolve_name(self.repo, self.verify_url, self.capture, self.config.name)

    def mark(self, *layer_names):
        """실행 계보 기록(중복 없이)."""
        for ln in layer_names:
            if ln and ln not in self.layers:
                self.layers.append(ln)
