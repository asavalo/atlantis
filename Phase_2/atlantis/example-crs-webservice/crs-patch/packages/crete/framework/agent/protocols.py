from typing import Iterator, Protocol

from crete.atoms.action import Action
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext


class AgentProtocol(Protocol):
    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]: ...
