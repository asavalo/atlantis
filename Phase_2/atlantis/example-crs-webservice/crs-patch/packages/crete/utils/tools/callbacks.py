from typing import Any

from crete.commons.logging.contexts import LoggingContext
from crete.utils.tools.functions import log_tool_call
from langchain.callbacks.base import BaseCallbackHandler


class LoggingCallbackHandler(BaseCallbackHandler):
    def __init__(self, context: LoggingContext):
        self._context = context

    def on_tool_start(
        self, serialized: dict[str, Any], input_str: str, **kwargs: Any
    ) -> None:
        tool_name = serialized.get("name", "unknown")
        log_tool_call(self._context, f"START {tool_name} - {input_str}")

    def on_tool_end(self, output: Any, **kwargs: Any) -> None:
        log_tool_call(self._context, f"SUCCESS {output}")

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        log_tool_call(self._context, f"ERROR {error}")
