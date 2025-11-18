import typing
from enum import Enum

from pydantic import BaseModel
from langchain_core.messages import BaseMessage

from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)


class SarifValidationAction(Enum):
    VALIDATE = "VALIDATE"
    RETRIEVE = "RETRIEVE"
    VALID = "VALID"
    INVALID = "INVALID"


class SarifValidationState(BaseModel):
    sarif: str
    src_dir: str
    messages: typing.List[BaseMessage] = list()
    retrieve_query: typing.Optional[str] = None
    retrieved: typing.Optional[str] = None
    next_action: str = SarifValidationAction.VALIDATE.value
