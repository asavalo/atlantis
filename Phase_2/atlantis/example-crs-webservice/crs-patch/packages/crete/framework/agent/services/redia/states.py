from pathlib import Path
from typing import Annotated, Any

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict

from crete.atoms.action import Action


class RediaState(TypedDict):
    messages: Annotated[list[Any], add_messages]
    target_files: list[Path]
    diff: bytes
    action: Action
