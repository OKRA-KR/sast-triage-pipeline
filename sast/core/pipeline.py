"""Stage 프로토콜 + 파이프라인 러너.

계획의 단계 구조(①URL확인→②엔드포인트 탐색→③인텔→④DAST→트리아지→LLM→리포트)를
코드로 드러낸다. 각 스테이지는 applies(ctx) 로 실행여부를 스스로 판단하고 run(ctx) 로
ctx 를 제자리에 채운다. cmd_scan 의 200줄 절차가 여기 순서 목록으로 대체돼 간다.

스트랭글러: 스테이지는 한 번에 하나씩 이 파이프라인으로 옮겨온다. 아직 안 옮긴 절차는
cmd_scan 에 남아 공존한다.
"""


class Stage:
    """스테이지 기반 클래스. name 은 layers(실행 계보)에 기록된다."""
    name = "stage"

    def applies(self, ctx) -> bool:
        return True

    def run(self, ctx) -> None:
        raise NotImplementedError


def run_pipeline(ctx, stages):
    """applies() 가 True 인 스테이지만 순서대로 run(). 각 스테이지는 ctx 를 제자리에 갱신한다."""
    for st in stages:
        try:
            if st.applies(ctx):
                st.run(ctx)
        except Exception as e:
            # 한 스테이지 실패가 전체를 죽이지 않도록 — 계보에 실패 표시하고 진행
            ctx.mark(f"{getattr(st, 'name', 'stage')}!err")
            print(f"[!] 스테이지 {getattr(st, 'name', 'stage')} 실패 — {str(e)[:120]}")
    return ctx
