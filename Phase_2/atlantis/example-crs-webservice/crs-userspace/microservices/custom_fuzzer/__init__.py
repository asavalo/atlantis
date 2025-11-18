from google.protobuf.message import Message
import logging

from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy
from libatlantis.service_utils import service_callback, configure_logger
from libCRS.otel import install_otel_logger
from libatlantis.constants import (
    CUSTOM_FUZZER_RUN_REQUEST_TOPIC,
    CUSTOM_FUZZER_RUN_RESPONSE_TOPIC,
    CUSTOM_FUZZER_STOP_REQUEST_TOPIC,
    CUSTOM_FUZZER_STOP_RESPONSE_TOPIC,
    HARNESS_BUILDER_RESULT_TOPIC,
)
from libatlantis.protobuf import (
    CustomFuzzerRunRequest,
    CustomFuzzerStopRequest,
    CustomFuzzerRunResponse,
    CustomFuzzerStopResponse,
    BuildRequestResponse,
)

from . import config
from .context import CustomFuzzerContext


logger = logging.getLogger("custom_fuzzer")


@service_callback(logger, CustomFuzzerRunRequest, "custom fuzzer run request")
def process_custom_fuzzer_run_request(
    input_message: CustomFuzzerRunRequest,
    thread_id: int,
    context: CustomFuzzerContext,
) -> list[Message]:
    return context.process_custom_fuzzer_run_request(input_message, thread_id)


@service_callback(logger, CustomFuzzerStopRequest, "custom fuzzer stop request")
def process_custom_fuzzer_stop_request(
    input_message: CustomFuzzerStopRequest,
    thread_id: int,
    context: CustomFuzzerContext,
) -> list[Message]:
    return context.process_custom_fuzzer_stop_request(input_message, thread_id)


@service_callback(logger, BuildRequestResponse, "build request response")
def process_build_request_response(
    input_message: BuildRequestResponse,
    thread_id: int,
    context: CustomFuzzerContext,
) -> list[Message]:
    return context.process_build_request_response(input_message, thread_id)


def run():
    configure_logger("custom_fuzzer")
    install_otel_logger(action_name="custom_fuzzer", action_category="fuzzing")
    logger.info("Start!")

    context = CustomFuzzerContext()

    custom_fuzzer_run_request_contexts = [
        context
    ] * config.NUM_CUSTOM_FUZZER_RUN_REQUEST_THREADS
    custom_fuzzer_run_request_runner = Runner(
        CUSTOM_FUZZER_RUN_REQUEST_TOPIC,
        CustomFuzzerRunRequest,
        config.GROUP_ID,
        CUSTOM_FUZZER_RUN_RESPONSE_TOPIC,
        config.NUM_CUSTOM_FUZZER_RUN_REQUEST_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_custom_fuzzer_run_request,
        custom_fuzzer_run_request_contexts,
    )

    custom_fuzzer_stop_request_contexts = [
        context
    ] * config.NUM_CUSTOM_FUZZER_STOP_REQUEST_THREADS
    custom_fuzzer_stop_request_runner = Runner(
        CUSTOM_FUZZER_STOP_REQUEST_TOPIC,
        CustomFuzzerStopRequest,
        config.GROUP_ID,
        CUSTOM_FUZZER_STOP_RESPONSE_TOPIC,
        config.NUM_CUSTOM_FUZZER_STOP_REQUEST_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_custom_fuzzer_stop_request,
        custom_fuzzer_stop_request_contexts,
    )

    build_request_response_contexts = [
        context
    ] * config.NUM_BUILD_REQUEST_RESPONSE_THREADS
    build_request_response_runner = Runner(
        HARNESS_BUILDER_RESULT_TOPIC,
        BuildRequestResponse,
        config.GROUP_ID,
        None,
        config.NUM_BUILD_REQUEST_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_build_request_response,
        build_request_response_contexts,
    )

    consumers = [
        custom_fuzzer_run_request_runner.execute_thread_pool(),
        custom_fuzzer_stop_request_runner.execute_thread_pool(),
        build_request_response_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
