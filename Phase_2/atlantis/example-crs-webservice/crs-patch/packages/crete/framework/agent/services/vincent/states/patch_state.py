from enum import Enum, auto
from crete.framework.agent.services.vincent.functions import LLMRequest
from langchain_core.messages import BaseMessage
from pydantic import BaseModel, ConfigDict
from crete.atoms.detection import Detection
from crete.atoms.action import Action, HeadAction


class PatchStage(Enum):
    INIT_ANALYSIS = auto()
    ANALYZE_ROOT_CAUSE = auto()
    ANALYZE_PROPERTY = auto()
    PATCH = auto()
    COMPILE_FEEDBACK = auto()
    VULNERABLE_FEEDBACK = auto()
    TEST_FEEDBACK = auto()
    DONE = auto()


class PatchState(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    patch_stage: PatchStage = PatchStage.INIT_ANALYSIS
    messages: list[BaseMessage] = []
    diff: bytes = b""
    detection: Detection | None = None
    requests: list[LLMRequest] = []
    rca_report: str | None = None
    properties: list[str] | None = None
    action: Action = HeadAction()
    feedback_cnt: int = 0
