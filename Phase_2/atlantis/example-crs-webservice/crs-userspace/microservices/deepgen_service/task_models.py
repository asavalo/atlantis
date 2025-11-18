from dataclasses import dataclass
from typing import Optional


@dataclass
class TaskParams:
    harness_id: str
    num_repeat: int = 1
    cache_type: Optional[str] = None
    priority: int = 1
    dev_attempts: int = 1
    dev_cost: float = 100.0


@dataclass
class OneShotTaskParams(TaskParams):
    task: str = "one_shot"


@dataclass
class DiffAnalysisTaskParams(TaskParams):
    task: str = "diff_analysis"


@dataclass
class CancelTaskParams(TaskParams):
    task: str = "cancel"
