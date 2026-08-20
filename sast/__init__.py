"""repo-무관 모듈형 SAST 코어 (오프라인, stdlib 전용).

구조:
  engines/   엔진 어댑터 (semgrep 지금, codeql 나중). run_all 이 fingerprint 로 병합.
  triage.py  rules/suppress.json 기반 오탐 억제 + 심각도 (LLM 불필요)
  report.py  고정 스키마 results.json + 자체완결 대시보드
  cli.py     python3 -m sast scan <target> --out <dir>
"""
__version__ = "2.0.0"
