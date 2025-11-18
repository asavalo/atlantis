from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.requests.handlers.base_request_handler import (
    BaseRequestHandler,
)

from crete.framework.agent.services.vincent.functions import (
    LLMRequest,
)


class RuntimeValueRequestHandler(BaseRequestHandler):
    def __init__(self, context: AgentContext):
        super().__init__(context)

    def handle_request(self, request: LLMRequest) -> str:
        return ""
