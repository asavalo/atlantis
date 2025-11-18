import logging
import os
import time
import asyncio
from pathlib import Path
from libatlantis.protobuf import (
    FuzzerRunResponse, 
    FuzzerLaunchAnnouncement, 
    FuzzerStopResponse,
    DirectedFuzzerResponse,
    FuzzerSeeds,
    CustomFuzzerRunResponse,
    SUCCESS,
    FAILURE,
    DF_RUN,
    DF_STOP,
    DF_SUCCESS,
    DF_FAILURE,
)
from libCRS.otel import install_otel_logger
from google.protobuf.message import Message
from libatlantis.service_utils import configure_logger, service_callback
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy
from libatlantis.constants import (
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
    FUZZER_SEED_ADDITIONS_TOPIC,
    CUSTOM_FUZZER_RUN_RESPONSE_TOPIC,
)

from . import config
from .context import SeedsCollectorContext, GENERAL_ORIGIN, DIRECTED_ORIGIN, CUSTOM_ORIGIN

logger = logging.getLogger(__name__)

@service_callback(logger, FuzzerLaunchAnnouncement, "fuzzer launch announcement")
def process_fuzzer_launch_announcement(
    input_message: FuzzerLaunchAnnouncement, thread_id: int, context: SeedsCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping launch announcement for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    logger.info(f"Received the LaunchAnnouncement for {input_message.harness_id}")
    harness_id = input_message.harness_id
    # different handler depending on fuzzing mode (i.e. honggfuzz differentiate corpus from crashes)
    corpus_paths = [Path(path) for path in input_message.corpus_paths]
    context.register_launch_announcement(harness_id, harness_id, corpus_paths, GENERAL_ORIGIN)
    context.start_monitoring()
    return []

@service_callback(logger, FuzzerStopResponse, "fuzzer stop request")
def process_fuzzer_stop_response(
    input_message: FuzzerStopResponse, thread_id: int, context: SeedsCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping stop response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    logger.info(f"Received the FuzzerStopResponse for {input_message.harness_id}")
    if input_message.status == SUCCESS:
        context.deactivate_harness(input_message.harness_id, GENERAL_ORIGIN)
    return []

@service_callback(logger, FuzzerRunResponse, "fuzzer run request")
def process_fuzzer_run_response(
    input_message: FuzzerRunResponse, thread_id: int, context: SeedsCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping run response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    logger.info(f"Received the FuzzerRunResponse for {input_message.harness_id}")
    if input_message.status == FAILURE:
        context.deactivate_harness(input_message.harness_id, GENERAL_ORIGIN)
    return []

@service_callback(logger, DirectedFuzzerResponse, "directed fuzzer response")
def process_directed_fuzzer_response(
    input_message: DirectedFuzzerResponse, thread_id: int, context: SeedsCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping directed response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    harness_id = input_message.harness_id
    session_id = input_message.fuzzer_session_id
    corpus_paths = [Path(input_message.corpus_path)]
    if input_message.cmd == DF_RUN and input_message.status == DF_SUCCESS:
        logger.info(f"{session_id} is running, register!")
        context.register_launch_announcement(harness_id, session_id, corpus_paths, DIRECTED_ORIGIN)
        context.start_monitoring()
    elif input_message.cmd == DF_STOP:
        logger.info(f"{session_id} is stopped, deregister!")
        context.deactivate_harness(session_id, DIRECTED_ORIGIN)
    return []

@service_callback(logger, CustomFuzzerRunResponse, "custom fuzzer run response")
def process_custom_fuzzer_run_response(
    input_message: CustomFuzzerRunResponse, thread_id: int, context: SeedsCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping custom fuzzer run response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    if input_message.status == SUCCESS:
        for harness_id in input_message.harness_ids:
            if input_message.aux == "afl":
                corpus_paths = [Path(input_message.corpus_path) / f"{core}/default/queue" for core in input_message.cores]
            else:
                corpus_paths = [Path(input_message.corpus_path)]
            context.register_launch_announcement(harness_id, f"{input_message.fuzzer_session_id}-{harness_id}", corpus_paths, CUSTOM_ORIGIN)
            context.start_monitoring()
    return []

@service_callback(logger, FuzzerSeeds, "fuzzer seeds")
def process_seed_additions(
    input_message: FuzzerSeeds, thread_id: int, context: SeedsCollectorContext
) -> list[Message]:
    context.process_seed_additions(input_message)
    return []

def run():
    configure_logger("seeds_collector")
    install_otel_logger(action_name="seeds_collector", action_category="seeds_sharing")
    logger.info("[Seeds Collector] Start!")

    SEED_SHARE_DIR = os.environ.get("SEED_SHARE_DIR", "not_set")
    while SEED_SHARE_DIR == "not_set":
        logger.info("Waiting for SEED_SHARE_DIR to be set")
        time.sleep(10)
        SEED_SHARE_DIR = os.environ.get("SEED_SHARE_DIR", "not_set")

    if SEED_SHARE_DIR == "not_set":
        logger.error("SEED_SHARE_DIR is not set")
        exit(1)

    context = SeedsCollectorContext(Path(SEED_SHARE_DIR), 65)  # 2 minutes interval

    request_contexts = [context] * config.NUM_SEEDS_COLLECTOR_THREADS
    request_runner = Runner(
        FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
        FuzzerLaunchAnnouncement,
        config.GROUP_ID,
        None,
        config.NUM_SEEDS_COLLECTOR_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_launch_announcement,
        request_contexts,
    )

    fuzzer_run_response_contexts = [context] * config.NUM_FUZZER_RUN_RESPONSE_THREADS
    fuzzer_run_response_runner = Runner(
        FUZZER_RUN_RESPONSE_TOPIC,
        FuzzerRunResponse,
        config.GROUP_ID,
        None,
        config.NUM_FUZZER_RUN_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_run_response,
        fuzzer_run_response_contexts,
    )

    fuzzer_stop_response_contexts = [context] * config.NUM_FUZZER_STOP_RESPONSE_THREADS
    fuzzer_stop_response_runner = Runner(
        FUZZER_STOP_RESPONSE_TOPIC,
        FuzzerStopResponse,
        config.GROUP_ID,
        None,
        config.NUM_FUZZER_STOP_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_stop_response,
        fuzzer_stop_response_contexts,
    )

    directed_fuzzer_response_contexts = [context] * config.NUM_DIRECTED_FUZZER_RESPONSE_THREADS
    directed_fuzzer_response_runner = Runner(
        DIRECTED_FUZZER_RESPONSE_TOPIC,
        DirectedFuzzerResponse,
        config.GROUP_ID,
        None,
        config.NUM_DIRECTED_FUZZER_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_directed_fuzzer_response,
        directed_fuzzer_response_contexts,
    )

    custom_fuzzer_run_response_contexts = [context] * config.NUM_CUSTOM_FUZZER_RUN_RESPONSE_THREADS
    custom_fuzzer_run_response_runner = Runner(
        CUSTOM_FUZZER_RUN_RESPONSE_TOPIC,
        CustomFuzzerRunResponse,
        config.GROUP_ID,
        None,
        config.NUM_CUSTOM_FUZZER_RUN_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_custom_fuzzer_run_response,
        custom_fuzzer_run_response_contexts,
    )

    seed_additions_contexts = [context] * config.NUM_SEED_ADDITIONS_THREADS
    seed_additions_runner = Runner(
        FUZZER_SEED_ADDITIONS_TOPIC,
        FuzzerSeeds,
        config.GROUP_ID,
        None,
        config.NUM_SEED_ADDITIONS_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_seed_additions,
        seed_additions_contexts,
    )

    consumers = [
        request_runner.execute_thread_pool(), 
        fuzzer_run_response_runner.execute_thread_pool(),
        fuzzer_stop_response_runner.execute_thread_pool(),
        directed_fuzzer_response_runner.execute_thread_pool(),
        custom_fuzzer_run_response_runner.execute_thread_pool(),
        #seed_additions_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
