import time

from crete.framework.scheduler.tracker.protocols import TrackerProtocol


class TimeTracker(TrackerProtocol):
    def __init__(self, max_time: float):
        self._max_time = max_time
        self._start_time = self._current_time()
        self._is_running = False

    def is_exhausted(self) -> bool:
        elapsed_time = self._current_time() - self._start_time
        return elapsed_time >= self._max_time

    def start(self) -> None:
        self._start_time = self._current_time()
        self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    def _current_time(self) -> float:
        return time.time()
