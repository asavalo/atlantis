import argparse
from dataclasses import dataclass

from google.protobuf.message import Message
from libmsa import Runner
from libmsa.thread.pool import QueuePolicy

from proto.message_three_pb2 import MessageThree
from proto.message_two_pb2 import MessageTwo


@dataclass
class JobContext:
    job: str


def create_contexts(job: str, num_threads: int):
    return [JobContext(job=f"{job}_{thread_id}") for thread_id in range(num_threads)]


def process_message(
    input_message: Message, thread_id: int, context: JobContext
) -> Message:
    if not isinstance(input_message, MessageTwo):
        raise TypeError("Expected input_message to be of type MessageTwo")
    input_name = input_message.name
    job = context.job

    new_name = f"{input_name}&{job}"
    indicator = thread_id == input_message.value

    return MessageThree(name=new_name, value=thread_id, indicator=indicator)


if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser()

    parser.add_argument("job_name", type=str, help="Name of the job to run")
    parser.add_argument("num_threads", type=int, help="Number of threads to use")
    parser.add_argument("input_topic", type=str, help="Name of the input topic")
    parser.add_argument("group_id", type=str, help="Group ID for the job")
    parser.add_argument("output_topic", type=str, help="Name of the output topic")

    args = parser.parse_args()

    job_name = args.job_name
    num_threads = args.num_threads
    input_topic = args.input_topic
    group_id = args.group_id
    output_topic = args.output_topic

    # Create contexts
    contexts = create_contexts(job_name, num_threads)

    # Create runner
    runner = Runner(
        input_topic,
        MessageTwo,
        group_id,
        output_topic,
        num_threads,
        QueuePolicy.ROUND_ROBIN,
        process_message,
        contexts,
    )
    # Execute runner
    runner.execute()
