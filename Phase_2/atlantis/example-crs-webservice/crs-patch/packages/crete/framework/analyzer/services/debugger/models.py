from dataclasses import dataclass
from typing import TypedDict, Union

FileAndLine = tuple[str, int]
FunctionName = str


class Breakpoint(TypedDict):
    location: Union[FileAndLine, FunctionName]
    expressions: list[str]


@dataclass
class RuntimeValue:
    value: str | None
    type: str | None
