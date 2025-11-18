import logging
from pathlib import Path
import traceback

from google.protobuf.message import Message
from libatlantis.constants import ARTIFACTS_DIR, HARNESS_BUILDER_REQUEST_TOPIC, HARNESS_BUILDER_RESULT_TOPIC
from libatlantis.protobuf import (
    CUSTOM,
    FAILURE,
    SUCCESS,
    BuildRequest,
    BuildRequestResponse,
    Mode,
    mode_to_string,
)
from libatlantis.service_utils import configure_logger, service_callback
from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy

from . import config
from .builder_impl import BuilderImpl


logger = logging.getLogger(__name__)

@service_callback(logger, BuildRequest, "build request")
def process_build_request(
    input_message: BuildRequest, thread_id: int, context: None
) -> list[Message]:
    if input_message.node_idx != config.NODE_IDX:
        logger.info(f"Skipping build request for node {input_message.node_idx} because we are node {config.NODE_IDX}")
        return []

    response = BuildRequestResponse()
    response.nonce = input_message.nonce
    response.mode = input_message.mode
    response.node_idx = input_message.node_idx

    try:
        builder = BuilderImpl(ARTIFACTS_DIR, config.STORAGE_DIR, config.HARNESS_SHARE_DIR)
        harnesses, cp_mount_path = builder.build(
            Path(input_message.oss_fuzz_path),
            input_message.cp_name,
            Path(input_message.cp_src_path),
            input_message.nonce,
            mode_to_string(input_message.mode),
        )
    except Exception as e:
        response.status = FAILURE
        response.aux = f"Build request for {mode_to_string(input_message.mode)} failed to process"

        tb_str = traceback.format_exc()
        logger.info("Full traceback:")
        logger.info(tb_str)
        return [response]

    # flush logs to always get harness builder logs
    for handler in logging.getLogger().handlers:
        handler.flush()

    if cp_mount_path is None:
        response.status = FAILURE
        response.aux = f"Build request for {mode_to_string(input_message.mode)} failed to process"

        return [response]

    response.status = SUCCESS
    response.aux = f"Build request for {mode_to_string(input_message.mode)} processed successfully"
    for key, value in harnesses.items():
        response.harnesses[key] = value
    response.cp_mount_path = cp_mount_path

    return [response]

def run():
    configure_logger("harness_builder")
    install_otel_logger(action_name="harness_builder", action_category="building")
    logger.info("Start!")
    config.STORAGE_DIR.mkdir(exist_ok=True)
    context = [None] * config.NUM_HARNESS_BUILDER_BUILD_THREADS
    br_runner = Runner(
        HARNESS_BUILDER_REQUEST_TOPIC,
        BuildRequest,
        config.GROUP_ID,
        HARNESS_BUILDER_RESULT_TOPIC,
        config.NUM_HARNESS_BUILDER_BUILD_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_build_request,
        context,
    )
    consumers = [br_runner.execute_thread_pool()]
    execute_consumers(consumers)
