from typing import Protocol

from crete.atoms.action import Action
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext


class ContextBuilderProtocol(Protocol):
    def build(
        self, previous_action: Action, reflection: str | None
    ) -> tuple[AgentContext, Detection]: ...
