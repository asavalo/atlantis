import logging
from collections import deque
from typing import Dict, Generic, List, Optional, TypeVar

T = TypeVar("T")  # Task type
R = TypeVar("R")  # Runner type


class RoundRobinScheduler(Generic[T, R]):
    def __init__(self, preserve_mode: bool = False):
        self.task_queues: Dict[T, deque[R]] = {}
        self.task_queue_order: deque[T] = deque()
        self.logger = logging.getLogger(__name__)
        self.preserve_mode = preserve_mode

    def put(self, task: T, runners: List[R]):
        self.logger.info(f"Queueing task: {task}")
        self.task_queues[task] = deque(runners)

        if task not in self.task_queue_order:
            self.task_queue_order.append(task)

    def get_next_task(self) -> Optional[T]:
        if not self.task_queue_order:
            return None

        task = self.task_queue_order[0]
        self.task_queue_order.rotate(-1)
        return task

    def get_next_runner(self, task: T) -> Optional[R]:
        if not self.task_queues.get(task):
            return None

        runners = self.task_queues[task]
        if not runners:
            return None

        runner = runners[0]
        if not self.preserve_mode:
            runners.popleft()
        else:
            runners.rotate(-1)
        return runner

    def remove_task(self, task: T):
        if task in self.task_queue_order:
            self.task_queue_order.remove(task)
        if task in self.task_queues:
            del self.task_queues[task]
