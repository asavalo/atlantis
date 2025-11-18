from libmsa import Producer
from controller.config import KAFKA_SERVER_ADDR
from controller.topics import CONTROLLER_CP_CONFIG_TOPIC
from controller.controller_pb2 import CPConfig

import argparse


def main():
    parser = argparse.ArgumentParser(description="Build Harness")
    parser.add_argument("--cp-path", type=str, required=True, help="CP root directory")
    args = parser.parse_args()

    producer = Producer(KAFKA_SERVER_ADDR, CONTROLLER_CP_CONFIG_TOPIC)
    req = CPConfig(cp_path=args.cp_path)
    producer.send_message(req)


if __name__ == "__main__":
    main()
