import typing
from enum import Enum

from pydantic import BaseModel
from langchain_core.messages import BaseMessage

from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)


class SarifMatchingAction(Enum):
    MATCHING = "MATCHING"
    RETRIEVE = "RETRIEVE"
    MATCHED = "MATCHED"
    NOT_MATCHED = "NOT_MATCHED"
    UNCERTAIN = "UNCERTAIN"


class SarifMatchingState(BaseModel):
    sarif: str
    src_dir: str
    testcase: typing.Optional[str] = None
    crash_log: typing.Optional[str] = None
    patch_diff: typing.Optional[str] = None
    messages: typing.List[BaseMessage] = list()
    retrieve_query: typing.Optional[str] = None
    retrieved: typing.Optional[str] = None
    next_action: str = SarifMatchingAction.MATCHING.value
