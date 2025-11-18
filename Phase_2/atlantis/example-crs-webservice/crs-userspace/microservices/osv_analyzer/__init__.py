import logging

from google.protobuf.message import Message
from libatlantis.constants import CP_CONFIG_TOPIC, OSV_ANALYZER_RESULTS_TOPIC, HARNESS_BUILDER_RESULT_TOPIC, FILE_OPS_RESPONSE_TOPIC
from libatlantis.protobuf import CPConfig, BuildRequestResponse, FileOpsResponse
from libatlantis.service_utils import configure_logger, service_callback
from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy

from . import config
from .analyze import OSVAnalyzer


logger = logging.getLogger(__name__)


@service_callback(logger, CPConfig, "CP config")
def process_cp_config(
    input_message: CPConfig, thread_id: int, context: OSVAnalyzer
) -> list[Message]:
    return context.process_cp_config(input_message)

@service_callback(logger, BuildRequestResponse, "Build request response")
def process_harness_builder_result(
    input_message: BuildRequestResponse, thread_id: int, context: OSVAnalyzer
) -> list[Message]:
    return context.process_harness_builder_result(input_message)

@service_callback(logger, FileOpsResponse, "File ops response")
def process_file_ops_response(
    input_message: FileOpsResponse, thread_id: int, context: OSVAnalyzer
) -> list[Message]:
    return context.process_file_ops_response(input_message)

def run():
    configure_logger("osv_analyzer")
    install_otel_logger(action_name="osv_analyzer", action_category="input_generation")
    logger.info("Start!")

    shared_context = OSVAnalyzer()
    contexts = [shared_context] * config.NUM_OSV_ANALYZER_THREADS
    runner = Runner(
        CP_CONFIG_TOPIC,
        CPConfig,
        config.GROUP_ID,
        None,
        config.NUM_OSV_ANALYZER_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_cp_config,
        contexts,
    )

    harness_builder_result_contexts = [shared_context] * config.NUM_OSV_ANALYZER_THREADS
    harness_builder_result_runner = Runner(
        HARNESS_BUILDER_RESULT_TOPIC,
        BuildRequestResponse,
        config.GROUP_ID,
        OSV_ANALYZER_RESULTS_TOPIC,
        config.NUM_OSV_ANALYZER_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_harness_builder_result,
        harness_builder_result_contexts,
    )

    file_ops_response_contexts = [shared_context] * config.NUM_OSV_ANALYZER_THREADS
    file_ops_response_runner = Runner(
        FILE_OPS_RESPONSE_TOPIC,
        FileOpsResponse,
        config.GROUP_ID,
        OSV_ANALYZER_RESULTS_TOPIC,
        config.NUM_OSV_ANALYZER_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_file_ops_response,
        file_ops_response_contexts,
    )

    consumers = [
        runner.execute_thread_pool(),
        harness_builder_result_runner.execute_thread_pool(),
        file_ops_response_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
