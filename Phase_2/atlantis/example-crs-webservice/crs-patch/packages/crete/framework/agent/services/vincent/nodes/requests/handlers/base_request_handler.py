from crete.framework.agent.contexts import AgentContext

from crete.framework.agent.services.vincent.functions import (
    LLMRequest,
)


class BaseRequestHandler:
    def __init__(self, context: AgentContext):
        self.context = context

    def handle_request(self, request: LLMRequest) -> str | None: ...
