import logging
from typing import Iterator

from crete.atoms.action import Action, SoundDiffAction
from crete.commons.logging.hooks import use_logger
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.scheduler.contexts import SchedulingContext
from crete.framework.scheduler.protocols import SchedulerProtocol
from crete.framework.scheduler.tracker import DefaultTracker


class RoundRobinScheduler(SchedulerProtocol):
    _logger: logging.Logger = use_logger()

    def __init__(self, early_exit: bool, max_rounds: int = 1):
        self._early_exit = early_exit
        self._max_rounds = max_rounds
        self._last_action: Action | None = None

    def schedule(
        self, context: SchedulingContext, agents: list[AgentProtocol]
    ) -> Iterator[AgentProtocol]:
        tracker = DefaultTracker(
            max_cost=context["llm_cost_limit"],
            max_time=context["timeout"],
        )

        with tracker.tracking():
            for _ in range(self._max_rounds):
                for agent in agents:
                    if self._should_early_exit():
                        self._logger.info("Found a sound diff action, exiting")
                        return

                    if tracker.is_exhausted():
                        self._logger.info("Resource limit reached, exiting")
                        return

                    yield agent

    def feedback(self, agent: AgentProtocol, action: Action):
        self._last_action = action

    def _should_early_exit(self) -> bool:
        return (
            self._early_exit
            and self._last_action is not None
            and isinstance(self._last_action, SoundDiffAction)
        )
