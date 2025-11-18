import base64
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
import time

from google.protobuf.message import Message
from libatlantis.constants import (
    ARTIFACTS_DIR,
    KAFKA_SERVER_ADDR,
    FUZZER_RUN_REQUEST_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_REQUEST_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    CORPUS_PATH_TOPIC,
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    NODE_NUM,
    NODE_CPU_CORES,
    IN_K8S,
)
from libatlantis.protobuf import (
    FuzzerRunRequest,
    FuzzerStopRequest,
    FuzzerRunResponse,
    FuzzerStopResponse,
    CorpusPathResult,
    FuzzerLaunchAnnouncement,
    SUCCESS,
    FAILURE,
    FUZZER_INIT,
    protobuf_repr,
)
from libatlantis.service_utils import configure_logger, service_callback
from libCRS.otel import install_otel_logger
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy
from libmsa.kafka import Producer

from . import config
from .context import FuzzerManagerContext

FUZZER_BASE_IMAGE = "ghcr.io/aixcc-finals/base-runner:v1.3.0"

logger = logging.getLogger(__name__)

def string_to_id(data: str, length: int=8) -> str:
    b64 = base64.b64encode(data.encode('utf-8'))
    return str(int.from_bytes(b64, byteorder='big') % (10 ** length)).zfill(length)

def get_fuzzer_session_id(nonce: str, harness_id: str, node_idx: int) -> str:
    return string_to_id(
        "fuzzer_session_id" + str(nonce) + str(harness_id) + str(node_idx)
    )

# WARNING: this ends the whole container!!!!!!!!
def send_fuzzer_run_response_failure(input_message: FuzzerRunRequest, session_id: str | None, context: FuzzerManagerContext, cores: list[int], aux: str="", time_left=None):
    if not time_left:
        time_left = get_time_left(input_message)
    if not session_id: # uncaught in previous testing??
        session_id = ""
    context.stop_session()
    response = FuzzerRunResponse()
    response.status = FAILURE
    response.harness_id = input_message.harness_id
    response.fuzzer_session_id = session_id
    response.node_idx = context.node_idx
    response.cores.extend(cores)
    response.aux = aux
    response.mode = input_message.mode
    response.stage = FUZZER_INIT
    response.time_left = time_left
    producer = Producer(KAFKA_SERVER_ADDR, FUZZER_RUN_RESPONSE_TOPIC)
    producer.send_message(response)
    # hacky way of killing tini itself
    logger.info("Fuzzer will now commit suicide")
    for handler in logging.getLogger().handlers:
        handler.flush()
    # subprocess.run(["kill", "-SIGTERM", "1"])
    os._exit(0)

def send_corpus_path_to_c_llm(corpus_path: Path, harness_id: str, fuzzer_session_id: str, binary_path: Path):
    producer = Producer(KAFKA_SERVER_ADDR, CORPUS_PATH_TOPIC)

    corpus_path_message = CorpusPathResult(
        fuzzer_session_id = fuzzer_session_id,
        corpus_path = str(corpus_path),
        harness_id = harness_id,
        fuzzer_binary_path = str(binary_path),
    )

    logger.info(f'Sending message: {protobuf_repr(corpus_path_message)}')
    producer.send_message(corpus_path_message)

def send_launch_announcement(ann: FuzzerLaunchAnnouncement):
    logger.info(f'Sending message: {protobuf_repr(ann)}')
    producer = Producer(KAFKA_SERVER_ADDR, FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC)
    producer.send_message(ann)

def get_time_left(input_message):
    return input_message.epoch_expiry - int(time.time())
    
def process_fuzzer_run_request_inner(
    input_message: FuzzerRunRequest,
    thread_id: int,
    context: FuzzerManagerContext,
) -> list[Message]:
    artifacts_dir = ARTIFACTS_DIR
    # step 0: setup work_dir and mount it to /out for the fuzzer
    work_dir = Path(f'/crs_scratch/fuzzer/{input_message.nonce}/{input_message.harness_id}')

    # step 1: determine fuzzer mode and get binary path
    cores = [int(core) for core in input_message.cores]

    match input_message.mode:
        case "afl":
            shared_binary = input_message.binary_paths.afl
        case "libafl":
            shared_binary = input_message.binary_paths.libafl
        case "libfuzzer":
            shared_binary = input_message.binary_paths.libfuzzer
        case "ubsan":
            shared_binary = input_message.binary_paths.ubsan
        case "msan":
            shared_binary = input_message.binary_paths.msan
        case "sans":
            shared_binary = input_message.binary_paths.sans
        case _:
            shared_binary = None

    if not shared_binary:
        send_fuzzer_run_response_failure(input_message, None, context, cores, aux=f"No fuzzer binary to run for mode {input_message.mode}")
        return []

    shared_binary = Path(shared_binary)
    fuzzer_mode = input_message.mode

    time_left = get_time_left(input_message)
    logger.info(f"Setting up fuzzer with mode: {fuzzer_mode} and {time_left}s timeout")

    # step 2: create appropriate fuzzer session
    try:
        initial_corpus_files = [Path(p) for p in input_message.corpus_files]
        dictionary_files = [Path(p) for p in input_message.dictionary_files]
        
        fuzzer, session_id = context.create_session(
            mode=fuzzer_mode,
            nonce=input_message.nonce,
            harness_id=input_message.harness_id,
            time_left=time_left,
            cores=cores,
            work_dir_path=work_dir,
            fuzzer_env=os.environ.copy(),
            initial_corpus_files=initial_corpus_files,
            dictionary_files=dictionary_files,
            binary=shared_binary,
            artifacts_dir=artifacts_dir,
        )
    except ValueError as e:
        send_fuzzer_run_response_failure(input_message, session_id, context, cores, aux=str(e))
        return []

    # step 3: run fuzzer
    fuzzer.run()

    if not fuzzer.check_fuzzer_successful():
        logger.error(f"check_fuzzer_successful failed")
        fuzzer.stop()
        fail_message = ""
        if fuzzer_mode == "libafl":
            fail_message = "***libafl runtime error, please fallback to afl*** no stats were created, init timed out"
        elif fuzzer_mode == "afl":
            fail_message = "***afl runtime error, please fallback to libfuzzer*** no stats were created, init timed out"
        else:
            fail_message = "libfuzzer failed to start"
        send_fuzzer_run_response_failure(input_message, session_id, context, cores, aux=fail_message, time_left=time_left)
        for handler in logging.getLogger().handlers:
            handler.flush()
        return []

    # step 4: send launch announcement
    # this should use the work_dir, not the mounted_work_dir
    send_launch_announcement(FuzzerLaunchAnnouncement(
        cp_name = input_message.cp_name,
        nonce = input_message.nonce,
        harness_id = input_message.harness_id,
        oss_fuzz_path = str(input_message.oss_fuzz_path),
        cp_src_path = input_message.cp_src_path,
        docker_image_name = FUZZER_BASE_IMAGE,
        binary_paths = input_message.binary_paths,
        cp_mount_path = input_message.cp_mount_path,
        node_idx = context.node_idx,
        crashes_paths = fuzzer.crashes_paths,
        corpus_paths = fuzzer.corpus_paths,
        mode = input_message.mode,
    ))
    
    response = FuzzerRunResponse()
    response.status = SUCCESS
    response.fuzzer_session_id = session_id
    response.harness_id = input_message.harness_id
    response.node_idx = context.node_idx
    response.cores.extend(cores)
    response.aux = f"Fuzzer is running in {fuzzer_mode} mode"
    response.stage = FUZZER_INIT
    response.mode = input_message.mode
    response.time_left = get_time_left(input_message)

    for handler in logging.getLogger().handlers:
        handler.flush()

    return [response]

@service_callback(logger, FuzzerRunRequest, "fuzzer run request")
def process_fuzzer_run_request(
    input_message: FuzzerRunRequest,
    thread_id: int,
    context: FuzzerManagerContext,
) -> list[Message]:
    with context.lock:
        try:
            if input_message.node_idx != context.node_idx:
                logger.info(f"Skipping run request for node {input_message.node_idx} because we are node {context.node_idx}")
                return []

            time_left = get_time_left(input_message)
            if time_left < 60:
                cores = [int(core) for core in input_message.cores]
                send_fuzzer_run_response_failure(input_message, None, context, cores, aux=f"Remaining epoch time is too short, {time_left} remaining", time_left=time_left)
                return []

            return process_fuzzer_run_request_inner(input_message, thread_id, context)
        except Exception as e:
            cores = [int(core) for core in input_message.cores]
            send_fuzzer_run_response_failure(input_message, None, context, cores, aux=f"Failed to process fuzzer run request: {e}")
            return []

@service_callback(logger, FuzzerStopRequest, "fuzzer stop request")
def process_fuzzer_stop_request(
    input_message: FuzzerStopRequest,
    thread_id: int,
    context: FuzzerManagerContext,
) -> list[Message]:
    with context.lock:
        # make sure the fuzzer run request is not processed while we are processing the stop request
        if input_message.node_idx != context.node_idx:
            logger.info(f"Skipping stop request for node {input_message.node_idx} because we are node {context.node_idx}")
            return []
        response = FuzzerStopResponse()
        fuzzer_session_id = input_message.fuzzer_session_id
        success = context.get_session(fuzzer_session_id)
        if success:
            cores = context.get_cores(fuzzer_session_id)
            context.stop_session(fuzzer_session_id)
            logger.info(f"Stopped session {fuzzer_session_id} with cores {cores}")
            response.status = SUCCESS
        else:
            response.status = FAILURE
        response.fuzzer_session_id = fuzzer_session_id
        response.harness_id = input_message.harness_id
        response.node_idx = context.node_idx
        producer = Producer(KAFKA_SERVER_ADDR, FUZZER_STOP_RESPONSE_TOPIC)
        producer.send_message(response)

        # bad things happen if we die on invalid stop response
        if success:
            # hacky way of killing tini itself
            logger.info("Fuzzer will now commit suicide")
            for handler in logging.getLogger().handlers:
                handler.flush()
            os._exit(0)
            #subprocess.run(["kill", "-SIGTERM", "1"])
    return []

def run():
    configure_logger("fuzzer_manager")
    install_otel_logger(action_name="fuzzer_manager", action_category="fuzzing")
    logger.info("Start!")
    context = FuzzerManagerContext()

    run_request_context = [context] * config.NUM_FUZZER_MANAGER_RUN_THREADS
    run_request_runner = Runner(
        FUZZER_RUN_REQUEST_TOPIC,
        FuzzerRunRequest,
        config.GROUP_ID,
        FUZZER_RUN_RESPONSE_TOPIC,
        config.NUM_FUZZER_MANAGER_RUN_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_run_request,
        run_request_context,
    )
    
    stop_request_context = [context] * config.NUM_FUZZER_MANAGER_STOP_THREADS
    stop_request_runner = Runner(
        FUZZER_STOP_REQUEST_TOPIC,
        FuzzerStopRequest,
        config.GROUP_ID,
        FUZZER_STOP_RESPONSE_TOPIC,
        config.NUM_FUZZER_MANAGER_STOP_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_stop_request,
        stop_request_context,
    )

    consumers = [run_request_runner.execute_thread_pool(), stop_request_runner.execute_thread_pool()]
    execute_consumers(consumers)
