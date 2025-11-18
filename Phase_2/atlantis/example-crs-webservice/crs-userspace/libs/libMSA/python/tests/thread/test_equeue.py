import random
import threading
import time
import unittest
from typing import List

from libmsa import EventfulQueue


class TestEventfulQueue(unittest.TestCase):
    def setUp(self) -> None:
        self.work_queue = EventfulQueue()
        self.terminate = False

    def enqueue_worker(self):
        for _ in range(100000):
            data = random.randint(0, 100000)
            self.work_queue.enqueue(data)

    def dequeue_worker(self):
        event = self.work_queue.get_event()
        while not self.terminate or event.is_set():
            event.wait()

            while True:
                data = self.work_queue.dequeue()
                if data is None:
                    break
                time.sleep(0.0001)
            self.work_queue.task_done()

    def test_single_thread_basic(self):
        data = 1

        self.assertFalse(self.work_queue.get_event().is_set())
        self.work_queue.enqueue(data)
        self.assertTrue(self.work_queue.get_event().is_set())
        self.work_queue.task_done()
        self.assertTrue(self.work_queue.get_event().is_set())
        ret = self.work_queue.dequeue()
        self.assertEqual(data, ret)
        ret = self.work_queue.dequeue()
        self.assertIsNone(ret)
        self.work_queue.task_done()
        self.assertFalse(self.work_queue.get_event().is_set())

    def test_multiple_thread_basic(self):
        num_enqueue_threads = 1
        num_dequque_threads = 10

        enqueue_threads: List[threading.Thread] = []
        dequeue_threads: List[threading.Thread] = []

        for _i in range(num_enqueue_threads):
            thread = threading.Thread(target=self.enqueue_worker, args=())
            enqueue_threads.append(thread)
            thread.start()

        for _ in range(num_dequque_threads):
            thread = threading.Thread(target=self.dequeue_worker, args=())
            dequeue_threads.append(thread)
            thread.start()

        for thread in enqueue_threads:
            thread.join()

        self.terminate = True

        for thread in dequeue_threads:
            thread.join()

        self.assertIsNone(self.work_queue.dequeue())


if __name__ == "__main__":
    unittest.main()
