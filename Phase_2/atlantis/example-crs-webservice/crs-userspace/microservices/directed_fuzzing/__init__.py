import logging

from libatlantis.constants import (
    DIRECTED_FUZZER_REQUEST_TOPIC,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
)

from libatlantis.protobuf import (
    DirectedFuzzerRequest,
    DF_RUN,
    DF_STOP,
)

from google.protobuf.message import Message
from libatlantis.service_utils import configure_logger, service_callback
from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy
from libmsa.kafka import Producer

from . import config
from .context import DirectedFuzzerContext

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@service_callback(logger, DirectedFuzzerRequest, "Directed Fuzzer")
def process_directed_fuzzer_request(
    input_message: DirectedFuzzerRequest,
    thread_id: int,
    context: DirectedFuzzerContext
) -> list[Message]:
    if input_message.node_idx != config.NODE_IDX:
        logger.info(f"Ignoring message for node:{input_message.node_idx}, we are node:{config.NODE_IDX}")
        for handler in logging.getLogger().handlers:
            handler.flush()
        return []

    if input_message.cmd == DF_RUN:
        context.process_run_request(input_message)
        for handler in logging.getLogger().handlers:
            handler.flush()
        return []
    elif input_message.cmd == DF_STOP:
        response = context.process_stop_request(input_message)
        for handler in logging.getLogger().handlers:
            handler.flush()
        return [response]

    return []

def run():
    configure_logger("directed_fuzzer")
    install_otel_logger(action_name="directed_fuzzer", action_category="fuzzing")
    logger.info("Start!")
    context = DirectedFuzzerContext()

    # flush logs to check health
    for handler in logging.getLogger().handlers:
        handler.flush()

    request_contexts = [context] * config.NUM_DIRECTED_FUZZER_THREADS
    request_runner = Runner(
        DIRECTED_FUZZER_REQUEST_TOPIC,
        DirectedFuzzerRequest,
        config.GROUP_ID,
        DIRECTED_FUZZER_RESPONSE_TOPIC,
        config.NUM_DIRECTED_FUZZER_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_directed_fuzzer_request,
        request_contexts,
    )

    consumers = [request_runner.execute_thread_pool()]
    execute_consumers(consumers)
