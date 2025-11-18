from typing import Protocol

from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.coder.contexts import CoderContext


class CoderProtocol(Protocol):
    """
    Defines the protocol for a coder that generates a diff.

    Methods:
        run: Generates a diff based on the given context and prompt.

    Attributes:
        agent_context: The context of the agent.
        detection: The detection to generate the diff for.
    """

    _agent_context: AgentContext
    _detection: Detection

    def __init__(self, agent_context: AgentContext, detection: Detection) -> None:
        self._agent_context = agent_context
        self._detection = detection

    def run(self, context: CoderContext, prompt: str) -> bytes | None: ...
