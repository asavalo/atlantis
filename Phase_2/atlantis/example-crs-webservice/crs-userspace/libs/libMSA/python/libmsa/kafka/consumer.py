from typing import Type, TypeVar

from confluent_kafka import Consumer as KafkaConsumer
from confluent_kafka import KafkaException
from google.protobuf.message import Message

T = TypeVar("T", bound=Message)


class Consumer:
    def __init__(
        self,
        bootstrap_server_addr: str,
        topic: str,
        group_id: str,
        protobuf_class: Type[T],
    ) -> None:
        self.bootstrap_server_addr = bootstrap_server_addr
        self.topic = topic
        self.group_id = group_id
        self.protobuf_class = protobuf_class

        self.consumer = KafkaConsumer(
            {
                "bootstrap.servers": self.bootstrap_server_addr,
                "group.id": self.group_id,
                "auto.offset.reset": "earliest",
                "enable.partition.eof": "false",
                "enable.auto.commit": "false",
                "session.timeout.ms": 6000,
                "heartbeat.interval.ms": 2000,
            }
        )
        self.consumer.subscribe([self.topic])

    def recv_message(self) -> Message | None:
        try:
            msg = self.consumer.poll(
                0.1
            )  # Poll for messages with a timeout of 1 second
            if msg is None:  # No messages available
                return None
            if msg.error():
                raise KafkaException(msg.error())

            self.consumer.commit()

            # Deserialize the Protobuf message
            deserialized_message = self.protobuf_class()
            msg_value = msg.value()
            if isinstance(msg_value, bytes):
                deserialized_message.ParseFromString(msg_value)
                return deserialized_message
            else:
                raise TypeError(
                    f"Message value cannot be a {type(msg_value)}. Expected bytes."
                )

        except Exception as e:
            print(f"Error while receiving message: {e}")
            return None

    def close(self):
        self.consumer.close()
