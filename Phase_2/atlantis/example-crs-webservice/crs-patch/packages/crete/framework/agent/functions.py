from typing import cast

from crete.commons.logging.contexts import LoggingContext
from crete.framework.agent.contexts import AgentContext


def store_debug_file(
    context: LoggingContext, name: str, content: str, log_output: bool = True
) -> None:
    agent_context = cast(AgentContext, context)
    if "output_directory" not in agent_context:
        return
    store_path = agent_context["output_directory"] / name
    store_path.parent.mkdir(parents=True, exist_ok=True)
    store_path.write_text(content)
    if log_output:
        context["logger"].info(f"{store_path}: {content}")


def append_debug_file(
    context: LoggingContext, name: str, content: str, log_output: bool = True
) -> None:
    agent_context = cast(AgentContext, context)
    if "output_directory" not in agent_context:
        return
    store_path = agent_context["output_directory"] / name
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with store_path.open("a") as f:
        f.write(content)
    if log_output:
        context["logger"].info(f"{store_path}: {content}")
