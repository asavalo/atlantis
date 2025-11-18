import argparse
import datetime

from harness_builder.config import KAFKA_SERVER_ADDR
from harness_builder.topics import HARNESS_BUILDER_REQUEST_TOPIC
from harness_builder.harness_builder_pb2 import BuildRequest, Mode
from libmsa import Producer


def main():
    parser = argparse.ArgumentParser(description="Build Harness")
    parser.add_argument("--cp-name", type=str, required=True, help="CP name")
    parser.add_argument("--cp-proj-path", type=str, required=True, help="CP project directory (i.e., the one with project.yaml)")
    parser.add_argument("--cp-src-path", type=str, required=True, help="CP source directory (i.e., its repository)")
    parser.add_argument("--cp-docker-image-name", type=str, required=True, help="Name of CP Docker image (assumed to already be built and available)")
    parser.add_argument("--mode", type=str, required=True, help="Build mode", choices=tuple(Mode.keys()))
    parser.add_argument("--aux", type=str, help="'Aux' string (meaning varies depending on build mode)")
    args = parser.parse_args()

    nonce = datetime.datetime.now().isoformat() \
        .replace('-', '_') \
        .replace(':', '_') \
        .replace('.', '_') \

    producer = Producer(KAFKA_SERVER_ADDR, HARNESS_BUILDER_REQUEST_TOPIC)
    req = BuildRequest(
        nonce = nonce,
        cp_name = args.cp_name,
        cp_proj_path = args.cp_proj_path,
        cp_src_path = args.cp_src_path,
        cp_docker_image_name = args.cp_docker_image_name,
        mode = args.mode,
        aux = args.aux,
    )
    producer.send_message(req)


if __name__ == "__main__":
    main()
