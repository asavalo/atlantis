import logging
import os
import time
from pathlib import Path
from libatlantis.protobuf import (
    DeepGenRequest,
    START,
    STOP,
    FuzzerRunResponse,
    FuzzerStopResponse,
    HarnessPrioritization,
    FuzzerLaunchAnnouncement,
)
from libCRS.otel import install_otel_logger
from google.protobuf.message import Message
from libatlantis.service_utils import configure_logger, service_callback
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy
from libatlantis.constants import (
    DEEPGEN_REQUEST_TOPIC,
    FUZZER_RUN_REQUEST_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_REQUEST_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    HARNESS_PRIORITIZATION_TOPIC,
)
from libatlantis.protobuf import SUCCESS

from . import config
from .context import DeepGenContext
from libCRS.util import run_cmd


logger = logging.getLogger(__name__)


@service_callback(logger, DeepGenRequest, "deepgen request")
def process_deepgen_request(
    input_message: DeepGenRequest, thread_id: int, context: DeepGenContext
) -> list[Message]:
    logger.info("Starting deepgen engine for node %d", context.node_idx)

    # poll in case config.yaml is still being written to
    dot_aixcc_config = (
        Path(input_message.oss_fuzz_path)
        / "projects"
        / input_message.cp_name
        / ".aixcc/config.yaml"
    )
    max_retries = 120
    for i in range(max_retries):
        if dot_aixcc_config.exists():
            break
        logger.warning(
            f"{dot_aixcc_config} is not generated yet, sleeping ({i}/{max_retries})"
        )
        time.sleep(1)
    else:
        logger.error(f"{dot_aixcc_config} is not found, returning")
        return []

    if input_message.msg_type == START:
        context.handle_engine_start(input_message)
    elif input_message.msg_type == STOP:
        logger.warning("experiemental stop request received (might have bugs)")
        context.handle_engine_stop(input_message)
    return []


@service_callback(logger, FuzzerRunResponse, "fuzzer run response")
def process_fuzzer_run_response(
    input_message: FuzzerRunResponse, thread_id: int, context: DeepGenContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(
            f"Received fuzzer run response for node {input_message.node_idx}, but current node is {context.node_idx}, skipping"
        )
        return []
    else:
        logger.info(f"Fuzzer run response received for node {input_message.node_idx} matched")
        context.handle_fuzzer_run(input_message)

    return []


@service_callback(logger, FuzzerStopResponse, "fuzzer stop response")
def process_fuzzer_stop_response(
    input_message: FuzzerStopResponse, thread_id: int, context: DeepGenContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(
            f"Received fuzzer stop response for node {input_message.node_idx}, but current node is {context.node_idx}, skipping"
        )
        return []
    else:
        logger.info(f"Fuzzer stop response received for node {input_message.node_idx} matched")
        context.handle_fuzzer_stop(input_message)
    return []


@service_callback(logger, FuzzerLaunchAnnouncement, "fuzzer launch announcement")
def process_fuzzer_launch_announcement(
    input_message: FuzzerLaunchAnnouncement, thread_id: int, context: DeepGenContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(
            f"Received fuzzer launch announcement for node {input_message.node_idx}, but current node is {context.node_idx}, skipping"
        )
        return []

    if input_message.mode == "libfuzzer":
        context.handle_libfuzzer_fallback(input_message)
    else:
        logger.info(
            f"Received fuzzer launch announcement for node {input_message.node_idx}, but we don't need to start it"
        )
    return []


@service_callback(logger, HarnessPrioritization, "harness prioritization")
def process_harness_prioritization(
    input_message: HarnessPrioritization, thread_id: int, context: DeepGenContext
) -> list[Message]:
    context.handle_harness_prioritization(input_message)
    return []


def run():
    configure_logger("deepgen_service")
    install_otel_logger(
        action_name="deepgen_service", action_category="deepgen_service"
    )
    logger.info("[DeepGen Service] Start!")

    logger.info(
        f"Configuring git with user name {config.GIT_USER_NAME} and email {config.GIT_USER_EMAIL}"
    )
    run_cmd(["git", "config", "--global", "user.name", config.GIT_USER_NAME])
    run_cmd(["git", "config", "--global", "user.email", config.GIT_USER_EMAIL])

    context = DeepGenContext()

    # 1. runner to control the deepgen engine
    deepgen_request_contexts = [context] * config.NUM_DEEPGEN_SERVICE_THREADS
    deepgen_request_runner = Runner(
        DEEPGEN_REQUEST_TOPIC,
        DeepGenRequest,
        config.GROUP_ID,
        None,
        config.NUM_DEEPGEN_SERVICE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_deepgen_request,
        deepgen_request_contexts,
    )

    # 2. runner to receive fuzzer run response (for each epoch)
    run_request_context = [context] * config.NUM_FUZZER_MANAGER_RUN_THREADS
    run_request_runner = Runner(
        FUZZER_RUN_RESPONSE_TOPIC,
        FuzzerRunResponse,
        config.GROUP_ID,
        FUZZER_RUN_REQUEST_TOPIC,
        config.NUM_FUZZER_MANAGER_RUN_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_run_response,
        run_request_context,
    )

    # 3. runner to receive fuzzer stop response (for each epoch)
    stop_request_context = [context] * config.NUM_FUZZER_MANAGER_STOP_THREADS
    stop_request_runner = Runner(
        FUZZER_STOP_RESPONSE_TOPIC,
        FuzzerStopResponse,
        config.GROUP_ID,
        FUZZER_STOP_REQUEST_TOPIC,
        config.NUM_FUZZER_MANAGER_STOP_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_stop_response,
        stop_request_context,
    )

    # 4. runner to receive fuzzer launch announcement
    launch_announcement_context = [context] * config.NUM_FUZZER_MANAGER_LAUNCH_THREADS
    launch_announcement_runner = Runner(
        FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
        FuzzerLaunchAnnouncement,
        config.GROUP_ID,
        None,
        config.NUM_FUZZER_MANAGER_LAUNCH_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_launch_announcement,
        launch_announcement_context,
    )

    # 5. harness prioritization
    harness_prioritization_context = [
        context
    ] * config.NUM_HARNESS_PRIORITIZATION_THREADS
    harness_prioritization_runner = Runner(
        HARNESS_PRIORITIZATION_TOPIC,
        HarnessPrioritization,
        config.GROUP_ID,
        None,
        config.NUM_HARNESS_PRIORITIZATION_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_harness_prioritization,
        harness_prioritization_context,
    )

    consumers = [
        deepgen_request_runner.execute_thread_pool(),
        run_request_runner.execute_thread_pool(),
        stop_request_runner.execute_thread_pool(),
        launch_announcement_runner.execute_thread_pool(),
        harness_prioritization_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
