import logging
import sys
import os
from asyncio.log import logger
from google.protobuf.message import Message

from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy
from libmsa.runner import Runner
from libatlantis.protobuf import SUCCESS
from libatlantis.constants import (
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
)
from libatlantis.protobuf import (
    FuzzerLaunchAnnouncement, 
    FuzzerStopResponse,
)
from libatlantis.service_utils import configure_logger, service_callback

from . import config
from .context import LLMMutatorContext

logger = logging.getLogger(__name__)

@service_callback(logger, FuzzerLaunchAnnouncement, "fuzzer launch announcement")
def process_fuzzer_launch_announcement(
    input_message: FuzzerLaunchAnnouncement, thread_id: int, context: LLMMutatorContext
 ) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping launch announcement for node {input_message.node_idx} because we are node {context.node_idx}")
        return []

    logger.info(f"Received the LaunchAnnouncement for {input_message.harness_id}")
    harness_id = input_message.harness_id
    if harness_id in context.active_harnesses:
        logger.error(f"{harness_id} is already active")
        return []

    context.register_launch_announcement(input_message)
    if context.monitor_start == False:
        context.monitor_start = True
        context.start_monitoring()
    return []

@service_callback(logger, FuzzerStopResponse, "fuzzer stop request")
def process_fuzzer_stop_response(
    input_message: FuzzerStopResponse, thread_id: int, context: LLMMutatorContext
 ) -> list[Message]:
    if input_message.node_idx != context.node_idx:
        logger.info(f"Skipping stop response for node {input_message.node_idx} because we are node {context.node_idx}")
        return []
    logger.info(f"Received the FuzzerStopResponse for {input_message.harness_id}")
    if input_message.status == SUCCESS:
        if input_message.harness_id not in context.active_harnesses:
            logger.error(f"{input_message.harness_id} is already not active")
            return []
        context.deactivate_harness(input_message.harness_id)
    return []

def run():
    configure_logger("c_llm_mutator")
    install_otel_logger(action_name="c_llm_mutator", action_category="input_generation")
    logger.info("[c_llm mutator] Start!")
    
    context = LLMMutatorContext(60) #2 minutes
    launch_contexts = [context] * config.NUM_LLM_MUTATOR_THREADS
    launch_runner = Runner(
        FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
        FuzzerLaunchAnnouncement,
        config.GROUP_ID,
        None,
        config.NUM_LLM_MUTATOR_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_launch_announcement,
        launch_contexts,
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

    execute_consumers([
        launch_runner.execute_thread_pool(),
        fuzzer_stop_response_runner.execute_thread_pool(),
    ])
    logger.info("[c_llm mutator] All consumers started")
