import argparse
import time

from osv_analyzer.config import KAFKA_SERVER_ADDR, GROUP_ID
from osv_analyzer.topics import CP_CONFIG_TOPIC, OSV_ANALYZER_RESULTS_TOPIC
from osv_analyzer.bootstrap_pb2 import CPConfig
from osv_analyzer.osv_analyzer_pb2 import OSVAnalyzerResult
from libmsa import Producer, Consumer


def main():
    parser = argparse.ArgumentParser(description="Trigger OSV analysis")
    parser.add_argument("--cp-name", type=str, required=True, help="CP name")
    parser.add_argument("--cp-proj-path", type=str, required=True, help="CP project directory (i.e., the one with project.yaml)")
    parser.add_argument("--cp-src-path", type=str, required=True, help="CP source directory (i.e., its repository)")
    parser.add_argument("--cp-docker-image-name", type=str, required=True, help="Name of CP Docker image")
    parser.add_argument("--listen", action="store_true", help="After sending request, also listen for responses")
    args = parser.parse_args()

    producer = Producer(KAFKA_SERVER_ADDR, CP_CONFIG_TOPIC)
    req = CPConfig(
        cp_name = args.cp_name,
        cp_proj_path = args.cp_proj_path,
        cp_src_path = args.cp_src_path,
        cp_docker_image_name = args.cp_docker_image_name,
    )
    producer.send_message(req)

    if args.listen:
        consumer = Consumer(
            KAFKA_SERVER_ADDR, OSV_ANALYZER_RESULTS_TOPIC, GROUP_ID, OSVAnalyzerResult
        )
        while True:
            msg = consumer.recv_message()
            if msg is None:
                time.sleep(0.5)
            else:
                print(f"Received message: {msg}")
                time.sleep(0.5)


if __name__ == "__main__":
    main()
