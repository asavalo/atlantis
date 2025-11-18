from pydantic import BaseModel
from enum import Enum


class LLMRequestType(Enum):
    DEFINITION = "definition"
    REFERENCE = "reference"
    SIMILAR = "similar"
    FILE = "file"
    RUNTIME_VALUE = "value"
    SHELL = "shell"
    IMPORT = "import"
    LINE = "line"
    JAVA_DEFINITION = "java_definition"
    ERROR = "error"


class LLMRequest(BaseModel):
    type: LLMRequestType
    targets: list[str] | None
    raw: str
