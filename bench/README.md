# bench — 정답셋 벤치마크 (P1-1)

스캐너가 **알려진 취약점을 얼마나 잡고(recall), 안전한 곳에 오탐을 얼마나 내는지(precision)**
측정한다. suppress/룰 변경의 **재현율 회귀를 잡는 그물**.

## 사용
```bash
python3 bench/run_bench.py vulnphp                 # 합성 타깃(정답 정확) — 스캔→측정
python3 bench/run_bench.py webgoat                 # 기존 out/WebGoat/results.json 대조
python3 bench/run_bench.py vulnphp --update-baseline   # 기준선 저장(baseline.json)
```
baseline 저장 후 재실행하면 **재현율↓ 또는 clean-FP↑ 시 회귀(⚠)로 종료코드 1**.

## 정답 정의 `expected/<name>.json`
- `scan_target`: 스캔할 경로(있으면 스캔) 또는 `results`: 기존 결과 경로(재사용).
- `expected[]`: `{category, path}` — 그 카테고리 finding 이 path 를 포함하면 recall hit.
- `clean[]`: `{group, path}` — 그 group finding 이 path 를 포함하면 FP(오탐).

## 타깃
- **vulnphp**(`apps/vulnphp/`): planted 취약 7종(vuln.php) + 안전 구현(safe.php=0건이어야).
  정답을 정확히 알아 **정밀 측정**에 씀. 값은 전부 합성(실데이터·실자격증명 없음).
- **webgoat**: WebGoat 레슨 설계(`lessons/<vulnclass>/`=의도적 취약)를 독립 근거로 한
  **부분 정답(recall 위주)**. 도구 출력에서 파생하지 않음. clean=정적/CI 자산.

> 확장: 새 대상은 `expected/<name>.json` 추가만으로. 실데이터·자격증명은 정답셋에 넣지 말 것.
