import sys
from .cli import main

for _s in (sys.stdout, sys.stderr):   # 한국어 Windows(cp949) 콘솔에서도 출력 안 깨지게
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if __name__ == "__main__":
    sys.exit(main())
