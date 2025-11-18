from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.vincent.nodes.requests.handlers.base_request_handler import (
    BaseRequestHandler,
)

from crete.framework.agent.services.vincent.functions import (
    LLMRequest,
)

"""
* Example:

[REQUEST:action] I want to check if the program uses any compiler-specific attributes or macros by running: grep -r "__attribute__\\|#define" . (shell:`grep -r "__attribute__\\|#define" .`) [/REQUEST:action]

"""


class ActionRequestHandler(BaseRequestHandler):
    def __init__(self, context: AgentContext):
        super().__init__(context)

    def handle_request(self, request: LLMRequest) -> str:
        return ""
