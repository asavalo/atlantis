from crete.framework.scheduler.tracker.llm_cost import LlmCostTracker
from crete.framework.scheduler.tracker.protocols import TrackerProtocol
from crete.framework.scheduler.tracker.time import TimeTracker


class DefaultTracker(TrackerProtocol):
    def __init__(self, max_time: float, max_cost: float) -> None:
        self._trackers = [
            TimeTracker(max_time),
            LlmCostTracker(max_cost),
        ]

    def is_exhausted(self) -> bool:
        return any(tracker.is_exhausted() for tracker in self._trackers)

    def start(self) -> None:
        for tracker in self._trackers:
            tracker.start()

    def stop(self) -> None:
        for tracker in self._trackers:
            tracker.stop()
