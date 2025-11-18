from abc import ABC, abstractmethod
import argparse
from pathlib import Path
import sys
import textwrap
import time

from google.protobuf.message import Message
from kafka import KafkaConsumer
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    CP_CONFIG_TOPIC,
    OSV_ANALYZER_RESULTS_TOPIC,
    HARNESS_BUILDER_REQUEST_TOPIC,
    HARNESS_BUILDER_RESULT_TOPIC,
    FUZZER_RUN_REQUEST_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    # FUZZER_STOP_REQUEST_TOPIC,
    # FUZZER_STOP_RESPONSE_TOPIC,
    # CRASH_COLLECTOR_CRASH_TOPIC,
    FUZZER_SEED_SUGGESTIONS_TOPIC,
    FUZZER_SEED_ADDITIONS_TOPIC,
)
from libatlantis.protobuf import CPConfig, OSVAnalyzerResult, BuildRequest, BuildRequestResponse, Mode, Status, FuzzerRunRequest, FuzzerRunResponse, FuzzerSeeds, protobuf_repr
from libmsa import Producer


GROUP_ID = 'send_script'
CONSUMER_BOILERPLATE_ARGS = {
    'bootstrap_servers': KAFKA_SERVER_ADDR,
    'group_id': GROUP_ID,
    'group_instance_id': GROUP_ID,
    'leave_group_on_close': False,
    'enable_auto_commit': True,
    'auto_commit_interval_ms': 100,
}

SCRIPT_DESCRIPTION = """
Script for sending a Kafka message and/or listening for response(s).
Mainly intended for testing and debugging.
"""
SCRIPT_EPILOG = f"""
examples:
  Send a message to the {CP_CONFIG_TOPIC} topic (like the bootstrap would) and listen for a response from the OSV Analyzer service:
    {sys.argv[0]} {CP_CONFIG_TOPIC} \\
      --cp-name=libpng \\
      --cp-proj-path=<path to oss-fuzz directory containing project.yaml> \\
      --cp-src-path=<path to CP repository> \\
      --cp-docker-image-name=libpng \\
      --listen={OSV_ANALYZER_RESULTS_TOPIC}
"""


class SendableTopic(ABC):
    """A Kafka topic the script is able to send messages to"""
    @property
    @abstractmethod
    def TOPIC(self) -> str:
        """The name of the topic"""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        """
        Add subparser arguments for creating an instance of the protobuf
        message class
        """
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        """
        Create an instance of the protobuf message class using collected
        argument values
        """
        raise NotImplementedError


class ReceivableTopic(ABC):
    """A Kafka topic the script is able to receive from"""
    @property
    @abstractmethod
    def TOPIC(self) -> str:
        """The name of the topic"""
        raise NotImplementedError

    @property
    @abstractmethod
    def MESSAGE_PROTOBUF_CLASS(self) -> Message:
        """The protobuf class to deserialize to"""
        raise NotImplementedError


def add_cp_field_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--cp-name', type=str, metavar='NAME', required=True,
        help='CP name')
    parser.add_argument('--cp-proj-path', type=Path, metavar='PATH', required=True,
        help='CP project directory (i.e., the one with project.yaml)')
    parser.add_argument('--cp-src-path', type=Path, metavar='PATH', required=True,
        help='CP source directory (i.e., its repository)')
    parser.add_argument('--cp-docker-image-name', type=str, metavar='NAME', required=True,
        help='name of CP Docker image')


def add_osv_analyzer_results_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--corpus-files', type=Path, metavar='PATH', nargs='*', required=True,
        help='path(s) to corpus files')
    parser.add_argument('--dictionary-files', type=Path, metavar='PATH', nargs='*', required=True,
        help='path(s) to dictionary files')


class Topic_CPConfig(SendableTopic, ReceivableTopic):
    """The CP config topic"""
    TOPIC = CP_CONFIG_TOPIC
    MESSAGE_PROTOBUF_CLASS = CPConfig

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        add_cp_field_args(parser)

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        return CPConfig(
            cp_name = args.cp_name,
            cp_proj_path = str(args.cp_proj_path.resolve()),
            cp_src_path = str(args.cp_src_path.resolve()),
            cp_docker_image_name = args.cp_docker_image_name,
        )


class Topic_OSVAnalyzerResults(SendableTopic, ReceivableTopic):
    """The OSV Analyzer results topic"""
    TOPIC = OSV_ANALYZER_RESULTS_TOPIC
    MESSAGE_PROTOBUF_CLASS = OSVAnalyzerResult

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        add_osv_analyzer_results_args(parser)

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        return OSVAnalyzerResult(
            corpus_files = [str(p.resolve()) for p in args.corpus_files],
            dictionary_files = [str(p.resolve()) for p in args.dictionary_files],
        )


class Topic_HarnessBuilderBuildRequest(SendableTopic, ReceivableTopic):
    """The harness-builder build-request topic"""
    TOPIC = HARNESS_BUILDER_REQUEST_TOPIC
    MESSAGE_PROTOBUF_CLASS = BuildRequest

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--nonce', type=str, required=True,
            help='nonce value, to match the response to the request')
        add_cp_field_args(parser)
        parser.add_argument('--mode', type=str, choices=tuple(Mode.keys()), required=True,
            help='instrumentation mode')
        parser.add_argument('--aux', type=str,
            help='optional auxiliary string (meaning varies depending on build mode)')

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        return BuildRequest(
            nonce = args.nonce,
            cp_name = args.cp_name,
            cp_proj_path = str(args.cp_proj_path.resolve()),
            cp_src_path = str(args.cp_src_path.resolve()),
            cp_docker_image_name = args.cp_docker_image_name,
            mode = args.mode,
            aux = args.aux or '',
        )


class Topic_HarnessBuilderBuildResult(SendableTopic, ReceivableTopic):
    """The harness-builder build-result topic"""
    TOPIC = HARNESS_BUILDER_RESULT_TOPIC
    MESSAGE_PROTOBUF_CLASS = BuildRequestResponse

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--nonce', type=str, required=True,
            help='nonce value, to match the response to the request')
        parser.add_argument('--status', type=str, choices=tuple(Status.keys()), required=True,
            help='whether the build was successful')
        parser.add_argument('--harnesses', type=str, metavar='NAME:PATH', nargs='*',
            help='names and binary paths of built harnesses (each name and path separated by a colon)')
        parser.add_argument('--aux', type=str,
            help='optional message (e.g., "Build completed successfully", or an error message)')

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        resolved_harnesses = []
        for h in args.harnesses:
            a, b = h.split(':')
            b = Path(b).resolve()
            resolved_harnesses.append(f'{a}:{b}')

        return BuildRequestResponse(
            nonce = args.nonce,
            status = args.status,
            harnesses = resolved_harnesses,
            aux = args.aux or '',
        )


class Topic_FuzzerRunRequest(SendableTopic, ReceivableTopic):
    """The fuzzer-run-request topic"""
    TOPIC = FUZZER_RUN_REQUEST_TOPIC
    MESSAGE_PROTOBUF_CLASS = FuzzerRunRequest

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        add_osv_analyzer_results_args(parser)
        parser.add_argument('--output-path', type=Path, metavar='PATH', required=True,
            help='directory to have the fuzzer write its outputs (corpus, etc.) to')
        parser.add_argument('--fuzzer-binary-path', type=Path, metavar='PATH', required=True,
            help='path to the fuzzer harness binary to run')
        parser.add_argument('--harness-id', type=str, required=True,
            help='name of the harness binary')
        parser.add_argument('--cores', type=str, metavar='ID', nargs='*', required=True,
            help='cores to assign to the fuzzer')

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        return BuildRequestResponse(
            corpus_files = [str(p.resolve()) for p in args.corpus_files],
            dictionary_files = [str(p.resolve()) for p in args.dictionary_files],
            output_path = str(args.output_path.resolve()),
            fuzzer_binary_path = str(args.fuzzer_binary_path.resolve()),
            harness_id = args.harness_id,
            cores = [int(core) for core in args.cores],
        )


class Topic_FuzzerRunResponse(SendableTopic, ReceivableTopic):
    """The fuzzer-run-response topic"""
    TOPIC = FUZZER_RUN_RESPONSE_TOPIC
    MESSAGE_PROTOBUF_CLASS = FuzzerRunResponse

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--status', type=str, choices=tuple(Status.keys()), required=True,
            help='whether the harness was launched successfully')
        parser.add_argument('--fuzzer-session-id', type=str, metavar='ID', required=True,
            help='new ID assigned to the fuzzing session')
        parser.add_argument('--aux', type=str,
            help='optional message')

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        return BuildRequestResponse(
            status = args.status,
            fuzzer_session_id = args.fuzzer_session_id,
            aux = args.aux or '',
        )


# Fuzzer stop request/response aren't implemented, so, skipping those

# Crash collector isn't implemented, so, skipping that


class FuzzerSeedsTopic:
    """Base class for topics using the FuzzerSeeds class"""
    MESSAGE_PROTOBUF_CLASS = FuzzerSeeds

    @classmethod
    def add_args(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument('--harness-id', type=str, required=True,
            help='name of the harness binary')
        parser.add_argument('--files', type=Path, metavar='PATH', nargs='+', required=True,
            help='file(s) to read the seed data from')

    @classmethod
    def create_message(cls, args: argparse.Namespace) -> Message:
        return FuzzerSeeds(
            harness_id = args.harness_id,
            origin = "send",
            data = [f.read_bytes() for f in args.files],
        )


class Topic_FuzzerSeedSuggestions(FuzzerSeedsTopic, SendableTopic, ReceivableTopic):
    """The fuzzer-seed suggestions topic"""
    TOPIC = FUZZER_SEED_SUGGESTIONS_TOPIC


class Topic_FuzzerSeedAdditions(FuzzerSeedsTopic, SendableTopic, ReceivableTopic):
    """The fuzzer-seed suggestions topic"""
    TOPIC = FUZZER_SEED_ADDITIONS_TOPIC


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(SCRIPT_DESCRIPTION.strip()),
        epilog=textwrap.dedent(SCRIPT_EPILOG.strip()),
    )

    parser.add_argument(
        '--listen',
        type=str,
        metavar='TOPIC,TOPIC,...',
        help='after sending the message (if any), also listen for messages on one or more topics (use "all" to listen on all known topics)',
    )

    subparsers = parser.add_subparsers(required=True)

    subparser = subparsers.add_parser('null',
        help="don't send any message (this allows you to use --listen by itself)")
    subparser.set_defaults(topic_cls=None)

    for topic_cls in sorted(SendableTopic.__subclasses__(), key=lambda cls: cls.TOPIC):
        subparser = subparsers.add_parser(topic_cls.TOPIC,
            help=f'send a message to the "{topic_cls.TOPIC}" topic')
        subparser.set_defaults(topic_cls=topic_cls)
        topic_cls.add_args(subparser)

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    receivable_message_classes = {cls.TOPIC: cls for cls in ReceivableTopic.__subclasses__()}

    classes_to_listen_with = []
    if args.listen:
        if args.listen == 'all':
            classes_to_listen_with.extend(receivable_message_classes.values())
        else:
            for part in args.listen.split(','):
                topic_cls = receivable_message_classes.get(part)
                if topic_cls is None:
                    raise ValueError(f'Unknown topic "{part}"')
                classes_to_listen_with.append(topic_cls)
            if not classes_to_listen_with:
                raise ValueError('--listen specified without any topics')

    if args.topic_cls is not None:
        print(f'Sending message to "{args.topic_cls.TOPIC}"...')
        producer = Producer(KAFKA_SERVER_ADDR, args.topic_cls.TOPIC)
        producer.send_message(args.topic_cls.create_message(args))

    if classes_to_listen_with:
        listen_topics = sorted(cls.TOPIC for cls in classes_to_listen_with)

        listen_topics_str = ', '.join(f'"{t}"' for t in listen_topics)
        print(f'Listening for messages on {listen_topics_str} (Ctrl+C to exit)...')

        consumer = KafkaConsumer(*listen_topics, **CONSUMER_BOILERPLATE_ARGS)
        start_time = time.time()

        try:
            for msg in consumer:
                print('----')
                print(f'Received message on topic "{msg.topic}" after {time.time() - start_time} seconds:')
                print(msg)

                topic_cls = receivable_message_classes[msg.topic]
                parsed = topic_cls.MESSAGE_PROTOBUF_CLASS()
                parsed.ParseFromString(msg.value)
                print(protobuf_repr(parsed))

        except KeyboardInterrupt:
            pass

        finally:
            # Close the consumer to commit our current offset
            consumer.close()


if __name__ == '__main__':
    main()
