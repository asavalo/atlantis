import logging
import os
import time
import asyncio
from pathlib import Path
import subprocess

from libatlantis.constants import (
    CRS_SCRATCH_DIR, 
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
)
from libatlantis.protobuf import (
    FuzzerLaunchAnnouncement,
    FuzzerRunResponse,
    FuzzerStopResponse,
    DirectedFuzzerResponse,
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

from . import config
from .context import CrashCollectorContext, GENERAL_ORIGIN, DIRECTED_ORIGIN, SARIF_ORIGIN

logger = logging.getLogger(__name__)


@service_callback(logger, FuzzerLaunchAnnouncement, "fuzzer launch announcement")
def process_fuzzer_launch_announcement(
    input_message: FuzzerLaunchAnnouncement, thread_id: int, context: CrashCollectorContext
) -> list[Message]:
    # add sarif pov path for node 0
    if context.node_idx == 0:
        SEED_SHARE_DIR = os.environ.get("SEED_SHARE_DIR")
        sarif_pov_path = Path(SEED_SHARE_DIR) / "crs-sarif" / input_message.harness_id
        crashes_paths = [sarif_pov_path]
        logger.info(f"We are node {context.node_idx}, registering sarif pov path for {input_message.harness_id}")
        context.activate_harness(input_message.harness_id, crashes_paths, SARIF_ORIGIN)
        context.start_monitoring()

    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping launch announcement for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    harness_id = input_message.harness_id
    crashes_paths = [Path(path) for path in input_message.crashes_paths]
    context.activate_harness(harness_id, crashes_paths, GENERAL_ORIGIN)
    context.start_monitoring()
    return []

@service_callback(logger, FuzzerRunResponse, "fuzzer run response")
def process_fuzzer_run_response(
    input_message: FuzzerRunResponse, thread_id: int, context: CrashCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping run response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    harness_id = input_message.harness_id
    if input_message.status == FAILURE:
        context.deactivate_harness(harness_id, GENERAL_ORIGIN)
    return []

@service_callback(logger, FuzzerStopResponse, "fuzzer stop request")
def process_fuzzer_stop_response(
    input_message: FuzzerStopResponse, thread_id: int, context: CrashCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping stop response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    if input_message.status == SUCCESS:
        context.deactivate_harness(input_message.harness_id, GENERAL_ORIGIN)
    return []

@service_callback(logger, DirectedFuzzerResponse, "directed fuzzer response")
def process_directed_fuzzer_response(
    input_message: DirectedFuzzerResponse, thread_id: int, context: CrashCollectorContext
) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping directed resonse for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    session_id = input_message.fuzzer_session_id
    harness_id = input_message.harness_id
    crashes_paths = [Path(input_message.crashes_path)]
    if input_message.cmd == DF_RUN and input_message.status == DF_SUCCESS:
        logger.info(f"{session_id} is running, register!")
        context.activate_harness(harness_id, crashes_paths, DIRECTED_ORIGIN, session_id)
        context.start_monitoring()
    elif input_message.cmd == DF_STOP:
        logger.info(f"{session_id} is stopped, deregister!")
        context.deactivate_harness(session_id, DIRECTED_ORIGIN)
    return []

def run():
    configure_logger("crash_collector")
    install_otel_logger(
        action_name="crash_collector", action_category="scoring_submission"
    )
    logger.info("[Crash Collector] Start!")
    logger.info("[Crash Collector] Note that crash collector depends on ensembler to be running")

    os.environ.update({
        "START_TIME": str(int(time.time())),
        "SANITIZER": os.environ.get("SANITIZER", "address"),
    })

    context = CrashCollectorContext()

    ann_contexts = [context] * config.NUM_CRASH_COLLECTOR_THREADS
    ann_runner = Runner(
        FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
        FuzzerLaunchAnnouncement,
        config.GROUP_ID,
        None,
        config.NUM_CRASH_COLLECTOR_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_launch_announcement,
        ann_contexts,
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
    
    consumers = [
        ann_runner.execute_thread_pool(), 
        fuzzer_stop_response_runner.execute_thread_pool(),
        fuzzer_run_response_runner.execute_thread_pool(),
        directed_fuzzer_response_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
