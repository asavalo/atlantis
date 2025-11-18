import threading
from enum import Enum
from typing import Any, Callable, List

from google.protobuf.message import Message

from ..thread.equeue import EventfulQueue


class QueuePolicy(Enum):
    GLOBAL = 0
    ROUND_ROBIN = 1
    BROADCAST = 2


class ThreadPool:
    def __init__(
        self,
        num_threads: int,
        queue_policy: QueuePolicy,
        func: Callable[[Message, int, Any], None],
        contexts: List[Any],
    ) -> None:
        if len(contexts) != num_threads:
            assert False, "Contexts should contain context for num_threads(can be None)"
        self.num_threads = num_threads
        self.queue_policy = queue_policy
        self.func = func
        self.contexts = contexts

        self.num_queues = 1 if queue_policy == QueuePolicy.GLOBAL else num_threads
        self.work_queues = (
            [EventfulQueue()]
            if queue_policy == QueuePolicy.GLOBAL
            else [EventfulQueue() for _ in range(self.num_queues)]
        )
        self.cur_queue = 0
        self.threads: List[threading.Thread] = []

        self.executed = False

        self._create_threads()

    def _enqueue_global(self, data: Message) -> None:
        self.work_queues[0].enqueue(data)

    def _enqueue_round_robin(self, data: Message) -> None:
        self.work_queues[self.cur_queue].enqueue(data)
        self.cur_queue = (self.cur_queue + 1) % self.num_queues

    def _enqueue_broadcast(self, data: Message) -> None:
        for i in range(self.num_queues):
            self.work_queues[i].enqueue(data)

    def enqueue(self, data: Message) -> None:
        if self.queue_policy == QueuePolicy.GLOBAL:
            return self._enqueue_global(data)
        if self.queue_policy == QueuePolicy.ROUND_ROBIN:
            return self._enqueue_round_robin(data)
        if self.queue_policy == QueuePolicy.BROADCAST:
            return self._enqueue_broadcast(data)
        assert False

    def worker(
        self,
        work_queue: EventfulQueue,
        func: Callable[[Message, int, Any], None],
        thread_id: int,
        context: Any,
    ) -> None:
        event = work_queue.get_event()
        while True:
            event.wait()

            while True:
                data = work_queue.dequeue()  # Non-blocking get
                if data is None:
                    break
                func(data, thread_id, context)

            work_queue.task_done()

    def _create_threads(self) -> None:
        for i in range(self.num_threads):
            func = self.func
            thread_id = i
            context: Any = self.contexts[thread_id]  # type: ignore

            work_queue = (
                self.work_queues[0]
                if self.queue_policy == QueuePolicy.GLOBAL
                else self.work_queues[thread_id]
            )

            thread = threading.Thread(
                target=self.worker, args=(work_queue, func, thread_id, context)
            )
            thread.daemon = True
            self.threads.append(thread)

    def execute(self) -> None:
        for thread in self.threads:
            thread.start()
        self.executed = True

    def create_more_threads(self, num_threads: int, contexts: List[Any]) -> None:
        if num_threads <= 0:
            return
        if len(contexts) != num_threads:
            assert False, "Contexts should contain context for num_threads(can be None)"

        self.contexts = self.contexts + contexts
        for i in range(self.num_threads, self.num_threads + num_threads):
            if self.queue_policy != QueuePolicy.GLOBAL:
                self.work_queues.append(EventfulQueue())

            func = self.func
            thread_id = i
            context = self.contexts[thread_id]

            work_queue = (
                self.work_queues[0]
                if self.queue_policy == QueuePolicy.GLOBAL
                else self.work_queues[thread_id]
            )

            thread = threading.Thread(
                target=self.worker, args=(work_queue, func, thread_id, context)
            )
            thread.daemon = True
            self.threads.append(thread)
            if self.executed:
                thread.start()

        self.num_threads += num_threads
        if self.queue_policy != QueuePolicy.GLOBAL:
            self.num_queues += num_threads
