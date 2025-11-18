import time
import unittest
from dataclasses import dataclass

from google.protobuf.message import Message

from libmsa import QueuePolicy, ThreadPool

from ..proto.sample_pb2 import SampleInputMessage


@dataclass
class MockContext:
    count: int


class TestEventfulQueue(unittest.TestCase):
    def setUp(self) -> None:
        self.pool = None

    def tearDown(self) -> None:
        pass

    def mock_function(
        self, data: Message, thread_id: int, context: MockContext
    ) -> None:
        if not isinstance(data, SampleInputMessage):
            raise TypeError("Expected data to be of type SampleInputMessage")
        context.count += 1

    def create_contexts(self, num_threads: int):
        return [MockContext(count=0) for _ in range(num_threads)]

    def test_broadcast_enqueue(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.BROADCAST,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        for queue in self.pool.work_queues:
            self.assertEqual(num_data, queue.queue.qsize())

        for context in contexts:
            self.assertEqual(0, context.count)

    def test_global_enqueue(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.GLOBAL,
            self.mock_function,
            contexts,
        )
        self.assertEqual(1, len(self.pool.work_queues))

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        self.assertEqual(num_data, self.pool.work_queues[0].queue.qsize())

        for context in contexts:
            self.assertEqual(0, context.count)

    def test_round_robin_enqueue(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 3000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.ROUND_ROBIN,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        for queue in self.pool.work_queues:
            self.assertEqual(num_data // num_threads, queue.queue.qsize())

        for context in contexts:
            self.assertEqual(0, context.count)

    def test_broadcast_dequeue(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.BROADCAST,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        self.pool.execute()

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        time.sleep(3)

        for queue in self.pool.work_queues:
            self.assertEqual(0, queue.queue.qsize())

        for context in contexts:
            self.assertEqual(num_data, context.count)

    def test_global_dequeue(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.GLOBAL,
            self.mock_function,
            contexts,
        )
        self.assertEqual(1, len(self.pool.work_queues))

        self.pool.execute()

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        time.sleep(3)

        self.assertEqual(0, self.pool.work_queues[0].queue.qsize())

    def test_round_robin_dequeue(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1002
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.ROUND_ROBIN,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        self.pool.execute()

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        time.sleep(3)

        for queue in self.pool.work_queues:
            self.assertEqual(0, queue.queue.qsize())

        for context in contexts:
            self.assertEqual(num_data // num_threads, context.count)

    def test_broadcast_enqueue_additional_threads(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.BROADCAST,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        additional_threads = 2
        additional_contexts = self.create_contexts(additional_threads)
        additional_data = 500
        self.pool.create_more_threads(additional_threads, additional_contexts)
        self.assertEqual(num_threads + additional_threads, len(self.pool.work_queues))

        for _ in range(additional_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        cnt1 = 0
        cnt2 = 0
        for queue in self.pool.work_queues:
            if queue.queue.qsize() == num_data + additional_data:
                cnt1 += 1
            elif queue.queue.qsize() == additional_data:
                cnt2 += 1

        self.assertEqual(cnt1, num_threads)
        self.assertEqual(cnt2, additional_threads)

        total_contexts = contexts + additional_contexts
        for context in total_contexts:
            self.assertEqual(0, context.count)

    def test_global_enqueue_additional_threads(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.GLOBAL,
            self.mock_function,
            contexts,
        )
        self.assertEqual(1, len(self.pool.work_queues))

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        additional_threads = 2
        additional_contexts = self.create_contexts(additional_threads)
        additional_data = 500
        self.pool.create_more_threads(additional_threads, additional_contexts)
        self.assertEqual(1, len(self.pool.work_queues))

        for _ in range(additional_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        self.assertEqual(
            num_data + additional_data, self.pool.work_queues[0].queue.qsize()
        )

        total_contexts = contexts + additional_contexts
        for context in total_contexts:
            self.assertEqual(0, context.count)

    def test_round_robin_enqueue_additional_threads(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 3000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.ROUND_ROBIN,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        additional_threads = 2
        additional_contexts = self.create_contexts(additional_threads)
        additional_data = 500
        self.pool.create_more_threads(additional_threads, additional_contexts)
        self.assertEqual(num_threads + additional_threads, len(self.pool.work_queues))

        for _ in range(additional_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        cnt1 = 0
        cnt2 = 0
        for queue in self.pool.work_queues:
            if queue.queue.qsize() == num_data // num_threads + additional_data // (
                num_threads + additional_threads
            ):
                cnt1 += 1
            elif queue.queue.qsize() == additional_data // (
                num_threads + additional_threads
            ):
                cnt2 += 1

        self.assertEqual(cnt1, num_threads)
        self.assertEqual(cnt2, additional_threads)

        total_contexts = contexts + additional_contexts
        for context in total_contexts:
            self.assertEqual(0, context.count)

    def test_broadcast_dequeue_additional_threads(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.BROADCAST,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        self.pool.execute()

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        additional_threads = 2
        additional_contexts = self.create_contexts(additional_threads)
        additional_data = 500
        self.pool.create_more_threads(additional_threads, additional_contexts)
        self.assertEqual(num_threads + additional_threads, len(self.pool.work_queues))

        for _ in range(additional_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        time.sleep(3)

        for queue in self.pool.work_queues:
            self.assertEqual(0, queue.queue.qsize())

        for context in contexts:
            self.assertEqual(num_data + additional_data, context.count)

        for context in additional_contexts:
            self.assertEqual(additional_data, context.count)

    def test_global_dequeue_additional_threads(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1000
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.GLOBAL,
            self.mock_function,
            contexts,
        )
        self.assertEqual(1, len(self.pool.work_queues))

        self.pool.execute()

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        additional_threads = 2
        additional_contexts = self.create_contexts(additional_threads)
        additional_data = 500
        self.pool.create_more_threads(additional_threads, additional_contexts)
        self.assertEqual(1, len(self.pool.work_queues))

        for _ in range(additional_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        time.sleep(3)

        self.assertEqual(0, self.pool.work_queues[0].queue.qsize())

    def test_round_robin_dequeue_additional_threads(self):
        num_threads = 3
        contexts = self.create_contexts(num_threads)
        num_data = 1002
        self.pool = ThreadPool(
            num_threads,
            QueuePolicy.ROUND_ROBIN,
            self.mock_function,
            contexts,
        )
        self.assertEqual(num_threads, len(self.pool.work_queues))

        self.pool.execute()

        for _ in range(num_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        additional_threads = 2
        additional_contexts = self.create_contexts(additional_threads)
        additional_data = 500
        self.pool.create_more_threads(additional_threads, additional_contexts)
        self.assertEqual(num_threads + additional_threads, len(self.pool.work_queues))

        for _ in range(additional_data):
            self.pool.enqueue(SampleInputMessage(num=1))

        time.sleep(3)

        for queue in self.pool.work_queues:
            self.assertEqual(0, queue.queue.qsize())

        for context in contexts:
            self.assertEqual(
                num_data // num_threads
                + additional_data // (num_threads + additional_threads),
                context.count,
            )

        for context in additional_contexts:
            self.assertEqual(
                additional_data // (num_threads + additional_threads), context.count
            )


if __name__ == "__main__":
    unittest.main()
