from typing import TypedDict


class SchedulingContext(TypedDict):
    timeout: int
    llm_cost_limit: float
