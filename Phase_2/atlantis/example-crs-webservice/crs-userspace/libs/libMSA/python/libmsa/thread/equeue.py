import queue
import threading
from typing import Any, Optional


class EventfulQueue:
    def __init__(self) -> None:
        self.queue: queue.Queue[Any] = queue.Queue()
        self.event = threading.Event()
        self.lock = threading.Lock()

    def enqueue(self, data: Any) -> None:
        with self.lock:
            self.queue.put(data)
            self.event.set()

    def dequeue(self) -> Optional[Any]:
        with self.lock:
            try:
                return self.queue.get(block=False)
            except queue.Empty:
                return None

    def task_done(self) -> None:
        with self.lock:
            if self.queue.empty():
                self.event.clear()

    def get_event(self) -> threading.Event:
        return self.event
