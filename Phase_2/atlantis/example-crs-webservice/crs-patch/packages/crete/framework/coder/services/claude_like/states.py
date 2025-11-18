from typing import (
    Annotated,
    Sequence,
    TypedDict,
)
from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class ClaudeLikeState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    retry_model_invoke: bool
