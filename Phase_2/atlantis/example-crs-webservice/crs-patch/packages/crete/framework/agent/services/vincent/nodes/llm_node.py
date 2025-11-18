from typing import Any

from .base_node import BaseNode
from crete.framework.agent.contexts import AgentContext
from python_llm.api.actors import LlmApiManager


class LLMNode(BaseNode):
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        self.llm = llm_api_manager.langchain_litellm()

    def _check_content_is_str(self, content: Any) -> str:
        if not isinstance(content, str):
            raise ValueError(f"Unexpected message content type: {type(content)}")
        return content

    def set_context(self, context: AgentContext) -> None:
        self.context = context
