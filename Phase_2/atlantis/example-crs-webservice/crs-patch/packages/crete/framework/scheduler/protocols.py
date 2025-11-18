from typing import Iterator, Protocol

from crete.atoms.action import Action
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.scheduler.contexts import SchedulingContext


class SchedulerProtocol(Protocol):
    def schedule(
        self, context: SchedulingContext, agents: list[AgentProtocol]
    ) -> Iterator[AgentProtocol]: ...

    def feedback(self, agent: AgentProtocol, action: Action): ...
