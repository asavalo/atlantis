from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Kind(Enum):
    FUNCTION = "function"
    CLASS = "class"
    VARIABLE = "variable"
    BLOCK = "block"
    TYPE_DEFINITION = "type_definition"
    IDENTIFIER = "identifier"


@dataclass(frozen=True)
class LanguageNode:
    kind: Kind
    # 0-based index, half-open interval
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    file: Path
    text: str
