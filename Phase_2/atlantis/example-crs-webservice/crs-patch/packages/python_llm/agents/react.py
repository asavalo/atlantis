import time
from typing import Sequence, Union

from crete.commons.logging.hooks import use_logger
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.errors import GraphRecursionError
from langgraph.prebuilt import create_react_agent  # type: ignore

from python_llm.api.actors import LlmApiManager

logger = use_logger(__name__)

_MAX_RETRIES = 5


def run_react_agent(
    main_llm_api_manager: LlmApiManager,
    tools: list[BaseTool],
    messages: Sequence[Union[AIMessage, HumanMessage, SystemMessage]],
    recursion_limit: int = 256,
    backup_llm_api_manager: LlmApiManager | None = None,
) -> str | None:
    chat_model = main_llm_api_manager.langchain_litellm()
    agent_executor = create_react_agent(chat_model, tools)
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            return agent_executor.invoke(
                {"messages": messages}, {"recursion_limit": recursion_limit}
            )["messages"][-1].content

        except GraphRecursionError:
            logger.warning(f"Attempt {attempt} failed with GraphRecursionError.")
            return None

        except Exception as e:
            logger.warning(f"Attempt {attempt} failed with {e.__class__.__name__}.")
            if attempt == _MAX_RETRIES:
                logger.warning("Max retries reached.")
                if backup_llm_api_manager is None:
                    logger.warning("No backup model provided. Returning None.")
                    return None
                logger.info("Retrying ReACT Agent with backup model...")
                return run_react_agent(
                    backup_llm_api_manager, tools, messages, recursion_limit
                )
            time.sleep(10)

    return None
