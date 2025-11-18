import logging
import os
from pathlib import Path
import shutil

from google.protobuf.message import Message
from libatlantis.constants import (
    HARNESS_BUILDER_REQUEST_TOPIC,
    HARNESS_BUILDER_RESULT_TOPIC,
    FUZZER_RUN_REQUEST_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    SARIF_HARNESS_REACHABILITY_TOPIC,
    CP_CONFIG_TOPIC,
    OSV_ANALYZER_RESULTS_TOPIC,
    SARIF_DIRECTED_TOPIC,
    DELTA_DIRECTED_TOPIC,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
    FILE_OPS_RESPONSE_TOPIC,
    NODE_NUM,
    CRS_SCRATCH_DIR,
)
from libatlantis.protobuf import (
  CPConfig,
  BuildRequestResponse,
  OSVAnalyzerResult,
  FuzzerRunResponse,
  FuzzerStopResponse,
  LibSarifHarnessReachability,
  SarifDirected,
  DeltaDirected,
  FileOpsResponse,
  CONFIG_GEN,
  LIBFUZZER,
  OPTIMIZED,
  DirectedFuzzerResponse,
)
from libatlantis.service_utils import configure_logger, service_callback
from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy

from . import config
from .context import BuildStatus, ControllerContext


logger = logging.getLogger(__name__)


@service_callback(logger, CPConfig, "CP config")
def process_cp_config(
    input_message: CPConfig, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.register_cp(input_message)

    # only send libfuzzer mode to generate config.yaml and store other msgs for later
    messages: list[Message] = []
    pending: list[Message] = []
    modes = []

    # PREPATCH mode in node_idx = 0 due to FS
    if input_message.mode == "delta":
        messages.append(context.request_build(input_message.cp_name, OPTIMIZED, 0, cp_src_path=str(CRS_SCRATCH_DIR / "prepatch")))
        modes.append(OPTIMIZED)

    idx_offset = len(messages) # because manually append message for prepatch

    modes.extend(config.MODES_TO_REQUEST_BUILDS_FOR)

    for idx, mode in enumerate(modes):
        node_idx = (idx + idx_offset) % NODE_NUM
        if mode not in config.DELAY_BUILD_MODES:
            messages.append(context.request_build(input_message.cp_name, mode, node_idx))
        else:
            pending.append(context.request_build(input_message.cp_name, mode, node_idx))

    if len(messages) == 0:
        logger.warning("Libfuzzer mode build request not found")
        messages = pending
    else:
        with context.lock:
            context.pending_build_requests = pending

    return messages


@service_callback(logger, BuildRequestResponse, "harness-builder")
def process_harness_builder_build_result(
    input_message: BuildRequestResponse, thread_id: int, context: ControllerContext
) -> list[Message]: 
    # chains into the other build modes if config gen is done
    messages = []
    if input_message.mode == CONFIG_GEN:
        with context.lock:
            messages = context.pending_build_requests
            context.pending_build_requests = []
    context.process_harness_builder_build_result(input_message)
    return messages


@service_callback(logger, OSVAnalyzerResult, "OSV Analyzer")
def process_osv_analyzer_result(
    input_message: OSVAnalyzerResult, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_osv_analyzer_result(input_message)
    return []

@service_callback(logger, FuzzerRunResponse, "fuzzer-manager")
def process_fuzzer_run_response(
    input_message: FuzzerRunResponse, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_fuzzer_run_response(input_message)
    return []

@service_callback(logger, FuzzerStopResponse, "fuzzer-manager")
def process_fuzzer_stop_response(
    input_message: FuzzerStopResponse, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_fuzzer_stop_response(input_message)
    return []

@service_callback(logger, LibSarifHarnessReachability, "harness-reachability")
def process_sarif_harness_reachability(
    input_message: LibSarifHarnessReachability, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_sarif_harness_reachability(input_message)
    return []


@service_callback(logger, SarifDirected, "Sarif Directed")
def process_sarif_directed(
    input_message: SarifDirected, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_sarif_directed(input_message)
    return []

@service_callback(logger, DeltaDirected, "Delta Directed")
def process_delta_directed(
    input_message: DeltaDirected, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_delta_directed(input_message)
    return []

@service_callback(logger, DirectedFuzzerResponse, "Directed Fuzzer")
def process_directed_fuzzer_response(
    input_message: DirectedFuzzerResponse, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_directed_fuzzer_response(input_message)
    return []

@service_callback(logger, FileOpsResponse, "File Ops Response")
def process_file_ops_response(
    input_message: FileOpsResponse, thread_id: int, context: ControllerContext
) -> list[Message]:
    context.process_file_ops_response(input_message)
    return []

def run():
    configure_logger("controller")
    install_otel_logger(action_name="controller", action_category="building")  # I guess?
    logger.info("Start!")
    context = ControllerContext()

    cp_contexts = [context] * config.NUM_CP_CONFIG_THREADS
    cp_runner = Runner(
        CP_CONFIG_TOPIC,
        CPConfig,
        config.GROUP_ID,
        HARNESS_BUILDER_REQUEST_TOPIC,
        config.NUM_CP_CONFIG_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_cp_config,
        cp_contexts,
    )

    builder_contexts = [context] * config.NUM_HARNESS_BUILDER_RESULT_THREADS
    builder_runner = Runner(
        HARNESS_BUILDER_RESULT_TOPIC,
        BuildRequestResponse,
        config.GROUP_ID,
        HARNESS_BUILDER_REQUEST_TOPIC,
        config.NUM_HARNESS_BUILDER_RESULT_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_harness_builder_build_result,
        builder_contexts,
    )

    osv_analyzer_results_contexts = [context] * config.NUM_OSV_ANALYZER_RESULT_THREADS
    osv_analyzer_results_runner = Runner(
        OSV_ANALYZER_RESULTS_TOPIC,
        OSVAnalyzerResult,
        config.GROUP_ID,
        None,
        config.NUM_OSV_ANALYZER_RESULT_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_osv_analyzer_result,
        osv_analyzer_results_contexts,
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

    sarif_harness_reachbilitiy_contexts = [context] * config.NUM_SARIF_HARNESS_REACHABILITY_THREADS
    sarif_harness_reachability_runner = Runner(
        SARIF_HARNESS_REACHABILITY_TOPIC,
        LibSarifHarnessReachability,
        config.GROUP_ID,
        None,
        config.NUM_SARIF_HARNESS_REACHABILITY_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_sarif_harness_reachability,
        sarif_harness_reachbilitiy_contexts,
    )

    sarif_directed_contexts = [context] * config.NUM_SARIF_DIRECTED_THREADS
    sarif_directed_runner = Runner(
        SARIF_DIRECTED_TOPIC,
        SarifDirected,
        config.GROUP_ID,
        None,
        config.NUM_SARIF_DIRECTED_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_sarif_directed,
        sarif_directed_contexts,
    )

    delta_directed_contexts = [context] * config.NUM_DELTA_DIRECTED_THREADS
    delta_directed_runner = Runner(
        DELTA_DIRECTED_TOPIC,
        DeltaDirected,
        config.GROUP_ID,
        None,
        config.NUM_DELTA_DIRECTED_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_delta_directed,
        delta_directed_contexts,
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

    file_ops_response_contexts = [context] * config.NUM_FILE_OPS_RESPONSE_THREADS
    file_ops_response_runner = Runner(
        FILE_OPS_RESPONSE_TOPIC,
        FileOpsResponse,
        config.GROUP_ID,
        None,
        config.NUM_FILE_OPS_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_file_ops_response,
        file_ops_response_contexts,
    )

    consumers = [
        cp_runner.execute_thread_pool(),
        builder_runner.execute_thread_pool(),
        osv_analyzer_results_runner.execute_thread_pool(),
        fuzzer_run_response_runner.execute_thread_pool(),
        fuzzer_stop_response_runner.execute_thread_pool(),
        sarif_harness_reachability_runner.execute_thread_pool(),
        sarif_directed_runner.execute_thread_pool(),
        delta_directed_runner.execute_thread_pool(),
        directed_fuzzer_response_runner.execute_thread_pool(),
        file_ops_response_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
