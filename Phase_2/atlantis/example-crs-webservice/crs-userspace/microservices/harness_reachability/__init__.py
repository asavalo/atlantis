import os
import asyncio
import logging
from pathlib import Path

from google.protobuf.message import Message

from libatlantis.constants import CP_CONFIG_TOPIC
from libatlantis.protobuf import CPConfig
from libCRS.otel import install_otel_logger
from libmsa.thread.pool import QueuePolicy
from libatlantis.service_utils import configure_logger, service_callback
from libmsa.runner import Runner, execute_consumers

from . import config
from .context import HarnessReachabilityContext

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("harness_reachability")

REACHABILITY_SHARE_DIR = os.environ.get("REACHABILITY_SHARE_DIR")
SARIF_SHARE_DIR = os.environ.get("SARIF_SHARE_DIR")

async def async_wrapper(coroutines):
    await asyncio.gather(*coroutines)

@service_callback(logger, CPConfig, "CP config")
def process_cp_config(
    input_message: CPConfig, thread_id: int, context: HarnessReachabilityContext
) -> list[Message]:
    logger.info(f"thread id {thread_id}")
    logger.info(f"get the input_message for cp_config, src_path = {input_message.cp_src_path}")

    context.register_cp(input_message)

    coroutines = []

    if REACHABILITY_SHARE_DIR:
        share_dir = Path(REACHABILITY_SHARE_DIR)
        if not share_dir.exists():
            share_dir.mkdir(parents=True, exist_ok=True)
        
        # Do not use the reachability results
        if input_message.mode == "delta":
            coroutines.append(context.start_monitoring(
                Path(REACHABILITY_SHARE_DIR),
                context.reachability_handler,
                time_handler = context.send_libsarif_reachability_results,
            ))
    else:
        logger.error("REACHABILITY_SHARE_DIR not set")

    if SARIF_SHARE_DIR:
        share_dir = Path(SARIF_SHARE_DIR)
        if not share_dir.exists():
            share_dir.mkdir(parents=True, exist_ok=True)
        coroutines.append(context.start_monitoring(
            Path(SARIF_SHARE_DIR),
            context.sarif_handler,
            scan_closure = context.scan_dir_1_level,
        ))
    else:
        logger.error("SARIF_SHARE_DIR not set")

    # flush logs before entering routines
    for handler in logging.getLogger().handlers:
        handler.flush()

    asyncio.run(async_wrapper(coroutines))

    assert False, "Unreachable code"
    return []


def run():
    #logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    configure_logger("harness_reachability")
    install_otel_logger(action_name="harness_reachability", action_category="static_analysis")
    logger.info("[harness_reachability] Start!")
    
    max_threads = config.NUM_CP_CONFIG_THREADS
    context = HarnessReachabilityContext()
    contexts = [context] * max_threads
    config_info_runner = Runner(
        CP_CONFIG_TOPIC,
        CPConfig,
        config.GROUP_ID,
        None,
        config.NUM_CP_CONFIG_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_cp_config,
        contexts[:config.NUM_CP_CONFIG_THREADS]
    )

    execute_consumers([
        config_info_runner.execute_thread_pool()
    ])
    logger.info("[harness_reachability] consumer started")
