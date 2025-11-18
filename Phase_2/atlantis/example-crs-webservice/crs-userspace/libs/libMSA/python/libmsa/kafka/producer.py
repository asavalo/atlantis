from confluent_kafka import Producer as KafkaProducer
from google.protobuf.message import Message


class Producer:
    def __init__(self, bootstrap_server_addr: str, topic: str) -> None:
        self.bootstrap_server_addr = bootstrap_server_addr
        self.topic = topic

        self.producer = KafkaProducer({"bootstrap.servers": self.bootstrap_server_addr})

    def send_message(self, protobuf_message: Message):
        try:
            serialized_message = protobuf_message.SerializeToString()

            self.producer.produce(self.topic, serialized_message)
            self.producer.flush()

        except Exception as e:
            print(f"Failed to send message: {e}")
