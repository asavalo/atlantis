import time

from crete.commons.logging.contexts import LoggingContext
from crete.framework.agent.functions import append_debug_file


def log_tool_call(context: LoggingContext, message: str) -> None:
    append_debug_file(
        context,
        "tool_calls.log",
        f"{time.strftime('%Y-%m-%d-%H-%M-%S')} - {message}\n",
    )
