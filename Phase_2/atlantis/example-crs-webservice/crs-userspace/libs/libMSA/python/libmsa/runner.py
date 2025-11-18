from typing import Any, Callable, List, Tuple, Type, TypeVar, Union
import os

from google.protobuf import message as _message

from .kafka.consumer import Consumer
from .kafka.producer import Producer
from .thread.pool import QueuePolicy, ThreadPool

T = TypeVar("T", bound=_message.Message)


class Runner:
    def __init__(
        self,
        input_topic: str,
        input_profobuf_class: Type[T],
        group_id: str,
        output_topic: str | None,
        num_threads: int,
        queue_policy: QueuePolicy,
        func: Callable[
            [_message.Message, int, Any],
            Union[_message.Message, List[_message.Message]],
        ],
        contexts: List[Any],
    ) -> None:
        self.input_topic = input_topic
        self.input_profobuf_class = input_profobuf_class
        self.group_id = group_id
        self.output_topic = output_topic
        self.num_threads = num_threads
        self.queue_policy = queue_policy
        self.func = func
        self.contexts = contexts

        self.kafka_server_addr = os.getenv("KAFKA_SERVER_ADDR")
        assert self.kafka_server_addr

        self.consumer = Consumer(
            self.kafka_server_addr,
            self.input_topic,
            self.group_id,
            self.input_profobuf_class,
        )

        self.producer = (
            Producer(self.kafka_server_addr, self.output_topic)
            if self.output_topic is not None
            else None
        )

        self.thread_pool = ThreadPool(
            self.num_threads, self.queue_policy, self.worker, self.contexts
        )

    def worker(self, data: _message.Message, thread_id: int, context: Any) -> None:
        output_message = self.func(data, thread_id, context)
        if self.producer is not None:
            if isinstance(output_message, list):
                for message in output_message:
                    self.producer.send_message(message)
            else:
                self.producer.send_message(output_message)

    def execute(self) -> None:
        self.thread_pool.execute()
        while True:
            input_message = self.consumer.recv_message()
            if input_message is not None:
                self.thread_pool.enqueue(input_message)

    def execute_thread_pool(self) -> Tuple[Consumer, ThreadPool]:
        self.thread_pool.execute()
        return self.consumer, self.thread_pool


def execute_consumers(consumers: List[Tuple[Consumer, ThreadPool]]) -> None:
    while True:
        for consumer, thread_pool in consumers:
            input_message = consumer.recv_message()
            if input_message is not None:
                thread_pool.enqueue(input_message)
