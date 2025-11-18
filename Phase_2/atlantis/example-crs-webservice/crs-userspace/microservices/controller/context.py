from dataclasses import dataclass
import enum
from collections import deque
import logging
from pathlib import Path
import secrets
from threading import Lock, RLock, Condition, Event, Thread
from typing import TypeAlias, Optional
import os
import subprocess
import random
import time
import uuid
import yaml

from google.protobuf.message import Message
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    FUZZER_RUN_REQUEST_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_REQUEST_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    HARNESS_PRIORITIZATION_TOPIC,
    DIRECTED_FUZZER_REQUEST_TOPIC,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
    DEEPGEN_REQUEST_TOPIC,
    CUSTOM_FUZZER_RUN_REQUEST_TOPIC,
    FILE_OPS_TOPIC,
    IN_K8S,
    NODE_NUM,
    NODE_CPU_CORES,
)
from libatlantis.protobuf import (
    CPConfig,
    BuildRequest,
    BuildRequestResponse,
    FuzzerRunRequest,
    FuzzerRunResponse,
    FuzzerStopRequest,
    FuzzerStopResponse,
    HarnessPrioritization,
    DirectedFuzzerRequest,
    DirectedFuzzerResponse,
    FileWrite,
    FileOps,
    DF_RUN,
    DF_STOP,
    DF_SUCCESS,
    DF_FAILURE,
    FuzzerBinaries,
    DeepGenRequest,
    SarifDirected,
    DeltaDirected,
    START,
    STOP,
    OSVAnalyzerResult,
    LibSarifHarnessReachability,
    SUCCESS,
    FAILURE,
    FUZZER_INIT,
    FUZZER_RUN,
    Mode,
    LIBAFL,
    SINGLE_INPUT,
    SINGLE_INPUT_SBCC,
    LIBFUZZER,
    DIRECTED,
    OPTIMIZED,
    LIBFUZZER_SBCC,
    CONFIG_GEN,
    AFL,
    HONGGFUZZ,
    UBSAN,
    MSAN,
    SANS,
    CustomFuzzerRunRequest,
    CustomFuzzerRunResponse,
    protobuf_repr,
    mode_to_string,
    string_to_mode,
)
from libmsa.kafka import Producer

from . import config
from .core_allocator import CoreAllocator
from .task_scheduler import (
    TaskScheduler,
    Task,
    TaskType,
    DirectedTaskScheduler,
    DirectedTask,
    DirectedTaskMetadata,
    DirectedTaskState,
)

Nonce: TypeAlias = str


logger = logging.getLogger(__name__)

EPOCH_UNSET = -1

class BuildStatus(enum.Enum):
    PENDING = enum.auto()
    FAILED = enum.auto()
    SUCCESS = enum.auto()

class HarnessReachableStatus(enum.Enum):
    UNSET = enum.auto()
    UNREACHABLE = enum.auto()
    COMPILER_UNREACHABLE = enum.auto() # in case everything is marked as unreachable

    def is_unreachable(self) -> bool:
        return self in {self.UNREACHABLE, self.COMPILER_UNREACHABLE}
    
class LocationHarnessReachableStatus(enum.Enum):
    UNSET = enum.auto()
    UNREACHABLE = enum.auto()
    NOTFOUND = enum.auto()
    REACHABLE = enum.auto()
    
@dataclass
class BuildInfo:
    cp_name: str
    mode: Mode.ValueType
    status: BuildStatus
    have_sent_fuzzer_run_request: bool
    harnesses: dict[str, str]

@dataclass
class FuzzerSessionInfo:
    fuzzer_task: Task
    node_idx: int
    cores: list[int]

@dataclass
class DirectedLaunchInfo:
    location: str
    harness_id: str
    sarif_id: Optional[str]

class ControllerContext:
    lock: RLock
    cp : CPConfig | None
    builds: dict[Nonce, BuildInfo]
    osv_analyzer_result: OSVAnalyzerResult | None
    cp_mount_path: str | None
    max_core: int
    fuzzer_sessions: dict[str, FuzzerSessionInfo]
    harness_to_fuzzer_binaries: dict[str, FuzzerBinaries]

    def __init__(self):
        self.lock = RLock()
        self.cp_config = None
        self.delta_mode = False
        self.timer_threads = {}
        self.builds = {}
        self.libfuzzer_nonce = None
        self.osv_analyzer_result = None
        self.cp_mount_path = None
        self.built_harnesses = []
        self.pending_build_requests = []
        self.directed_locations = []
        self.pending_directed_locations = []
        self.pending_directed_tasks: list[DirectedTask] = []
        self.other_optimized_build = None
        self.directed_info = None
        self.directed_nonce = None
        self.directed_built_harnesses = []
        self.fuzzer_sessions = {}
        self.harness_to_fuzzer_binaries = {}
        self.harness_reachable_status = {}  # Maps harness_id to reachability status (-1, 0, 1)
        self.location_to_harness_to_reachability = {} # directed location -> harness -> reachability status
        self.harness_reachable_ignore = False  # Signals when everything is unreachable, prevent disabling all fuzzers
        self.done_optimized_builds = False
        self.pending_fuzzer_requests = 0
        self.received_reachability_results = False
        self.file_ops_processed = False # filthy flags!!!
        self.config_gen_processed = False
        self.config_gen_failed = False
        self.no_pending_fuzzer_requests_condition = Condition(self.lock)
        reserved_cores = [config.CORE_NUM_FOR_PER_CP_SERVICES + config.CORE_NUM_FOR_PER_NODE_SERVICES] + [config.CORE_NUM_FOR_PER_NODE_SERVICES] * (NODE_NUM - 1)
        self.core_allocator = CoreAllocator(num_nodes=NODE_NUM, core_per_node=NODE_CPU_CORES, reserved_cores=reserved_cores)
        self.current_epoch = EPOCH_UNSET
        self.current_directed_epoch = EPOCH_UNSET
        self.epoch_event = Event()
        self.directed_epoch_cond = Condition(self.lock)
        self.task_scheduler = TaskScheduler(num_sessions=NODE_NUM)
        self.directed_task_scheduler = DirectedTaskScheduler(num_sessions=NODE_NUM)
        self.fuzzer_run_request_producer = Producer(KAFKA_SERVER_ADDR, FUZZER_RUN_REQUEST_TOPIC)
        self.fuzzer_stop_request_producer = Producer(KAFKA_SERVER_ADDR, FUZZER_STOP_REQUEST_TOPIC)
        self.directed_fuzzer_producer = Producer(KAFKA_SERVER_ADDR, DIRECTED_FUZZER_REQUEST_TOPIC)
        self.harness_prioritization_producer = Producer(KAFKA_SERVER_ADDR, HARNESS_PRIORITIZATION_TOPIC)
        self.continue_epoch = False
        self.epoch_expiry = time.time()
        self.timeout_flag = False
        self.timeout_thread = None

    def _start_timeout_thread(self):
        def timeout_func():
            time.sleep(3600)  # 1 hour
            if self.current_epoch != EPOCH_UNSET:
                logger.info("Epoch already started, skipping timeout override") # tested
                return
            logger.warning("Timeout flag set after 1 hour. Forcing fuzzer start condition.")
            with self.lock:
                self.timeout_flag = True
                if not self.osv_analyzer_result:
                    self.osv_analyzer_result = OSVAnalyzerResult(
                        corpus_files=[],
                        dictionary_files=[],
                        project_names=[],
                        cp_src_path=self.cp_config.cp_src_path,
                    )
                self.register_builds() # tested
        t = Thread(target=timeout_func, daemon=True)
        t.start()
        self.timeout_thread = t

    def register_cp(self, config: CPConfig) -> None:
        """Notify the context about a new CP"""
        with self.lock:
            self.cp_config = config
            self.delta_mode = config.mode == "delta"
            if self.timeout_thread is None:
                self._start_timeout_thread()

    def request_build(self, cp_name: str, mode: Mode.ValueType, node_idx: int, cp_src_path: str = None) -> BuildRequest:
        """Create a message requesting a build of the given CP with the given mode"""
        with self.lock:
            if not self.cp_config.cp_name == cp_name:
                logger.error("CP name does not match")
                return []
            nonce = secrets.token_hex()

            self.builds[nonce] = BuildInfo(
                cp_name = cp_name,
                mode = mode,
                status = BuildStatus.PENDING,
                have_sent_fuzzer_run_request = False,
                harnesses = {},
            )

            if cp_src_path is None:
                cp_src_path = self.cp_config.cp_src_path

            return BuildRequest(
                nonce=nonce,
                oss_fuzz_path=self.cp_config.oss_fuzz_path,
                cp_name=cp_name,
                cp_src_path=cp_src_path,
                mode=mode,
                aux='',
                node_idx=node_idx,
            )

    def process_harness_builder_build_result(self, message: BuildRequestResponse):
        with self.lock:
            build_info = self.builds.get(message.nonce)
            if build_info is None:
                logger.warning(f'Unrecognized nonce: {message.nonce}')
                return []

            if message.status == FAILURE:
                logger.warning(f'Build "{message.nonce}" apparently failed: {message.aux}')
                build_info.status = BuildStatus.FAILED
            else:
                build_info.status = BuildStatus.SUCCESS
                for name, path in message.harnesses.items():
                    if path:
                        build_info.harnesses[name] = path

                # create config.yaml if failed.
                # do it here because need to wait for successful built_harnesses
                # cannot do it in register_builds() because that's a deadlock
                if self.config_gen_failed:
                    conf = {"harness_files": []}
                    for harness in message.harnesses.keys():
                        conf["harness_files"].append({"name": harness})
                    write_ops = self.__create_config_yaml(
                        conf,
                        Path(self.cp_config.oss_fuzz_path),
                        self.cp_config.cp_name,
                    )
                    producer = Producer(KAFKA_SERVER_ADDR, FILE_OPS_TOPIC)
                    producer.send_message(FileOps(writes=write_ops, extractions=[]))
                    self.config_gen_failed = False

                if self.cp_mount_path is None:
                    logger.info(f"Setting cp_mount_path! {message.cp_mount_path}")
                    self.cp_mount_path = message.cp_mount_path

            if build_info.mode == DIRECTED:
                self.prepare_directed_fuzzer_requests_if_needed()
            elif build_info.mode == CONFIG_GEN:
                if message.status == FAILURE: # launch if FileOps may have not been sent
                    # "fake" the file ops processed if config_gen filas
                    self.file_ops_processed = True
                    self.config_gen_failed = True
                self.config_gen_processed = True
                self.request_deepgen_launch()
            elif build_info.mode == OPTIMIZED:
                self.process_optimized_build(build_info)

            # do last in case of side effects from other modes (i.e. optimized)
            self.register_builds()


    def process_osv_analyzer_result(
        self, osv_analyzer_result_message: OSVAnalyzerResult
    ):
        with self.lock:
            self.osv_analyzer_result = osv_analyzer_result_message
            self.register_builds()
            self.prepare_directed_fuzzer_requests_if_needed()

    def process_file_ops_response(
        self, input_message
    ):
        with self.lock:
            # one shot pattern, condition handled in deepgen
            self.file_ops_processed = True
            self.deepgen_launched = self.request_deepgen_launch()

    def process_custom_fuzzer_run_response(self, input_message: CustomFuzzerRunResponse):
        with self.lock:
            if input_message.status == FAILURE:
                logger.error(f"Custom fuzzer run failed: {input_message.aux}")
                self.core_allocator.free_cores(input_message.node_idx, input_message.cores)
            else:
                logger.info("Custom fuzzer run succeeded")

    def process_delta_directed(
        self, delta_directed: DeltaDirected
    ):
        with self.lock:
            self.directed_locations.extend(delta_directed.locations)
            self.pending_directed_locations.extend(delta_directed.locations)
            self.prepare_directed_fuzzer_requests_if_needed()

    def process_sarif_directed(
        self, sarif_directed: SarifDirected
    ):
        with self.lock:
            task = DirectedTask(
                type_ = TaskType.DIRECTED_FUZZER,
                location = sarif_directed.location,
                harness_id = sarif_directed.harness_id,
                sarif_id = sarif_directed.sarif_id,
                fuzzer_session_id = str(uuid.uuid4()),
            )
            self.directed_locations.insert(0, sarif_directed.location)
            self.pending_directed_tasks.append(task)
            self.prepare_directed_fuzzer_requests_if_needed()

    def __create_config_yaml(
        self,
        conf: dict[any, any],
        oss_fuzz_path: Path,
        cp_name: str,
    ) -> list[FileWrite]:
        cp_proj_path = oss_fuzz_path / "projects" / cp_name

        write_ops = []
        conf_path = cp_proj_path / ".aixcc/config.yaml"
        tmp_conf_path = cp_proj_path / ".aixcc/config.yaml.tmp"

        # copy config.yaml to config.yaml.tmp
        if conf_path.exists():
            original_conf = conf_path.read_bytes()
            write_ops.append(FileWrite(
                file_path=str(tmp_conf_path),
                content=original_conf,
            ))

        # write to new config.yaml
        conf_str = yaml.dump(conf)
        write_ops.append(FileWrite(
            file_path=str(conf_path),
            content=conf_str.encode('utf-8'),
        ))

        return write_ops

    def __update_location_reachability(self):
        # for each location,
        # if all are unreachable then do nothing
        # if some are unreachable then mark those harnesses as UNREACHABLE

        logger.info(f"Entered update_location_reachability. Dumping: {self.location_to_harness_to_reachability}")
        if not self.built_harnesses:
            logger.error("No built harnesses")
            return
        unreachable_harnesses = set()
        compiler_unreachable_harnesses = set(harness
                                             for harness, status in self.harness_reachable_status.items()
                                             if status == HarnessReachableStatus.COMPILER_UNREACHABLE)
        for location in self.directed_locations:
            if location not in self.location_to_harness_to_reachability:
                self.location_to_harness_to_reachability[location] = {}
            harness_map = self.location_to_harness_to_reachability[location]
            logger.info(f"We're checking reachability for {location}")
            if len(harness_map.keys()) < 2: # only do logic if we have harnesses to compare against
                logger.info(f"The location {location} doesn't have enough results to compare")
                continue
            
            # check if all are unreachable or not found
            if all(status == LocationHarnessReachableStatus.UNREACHABLE or status == LocationHarnessReachableStatus.NOTFOUND for status in harness_map.values()):
                # don't consider this location
                logger.info(f"The location {location} has all harnesses either unreachable or not found")
                continue

            iteration_unreachable_harnesses = set()
            for harness, status in harness_map.items():
                if status == LocationHarnessReachableStatus.UNREACHABLE:
                    iteration_unreachable_harnesses.add(harness)
            if iteration_unreachable_harnesses | unreachable_harnesses == set(self.harness_reachable_status.keys()):
                logger.info(f"All harnesses are unreachable by location {location}, so we ignore this location and the rest")
                break
            unreachable_harnesses |= iteration_unreachable_harnesses
            logger.info(f"Unreachable harnesses collected so far {unreachable_harnesses}")

        for harness in self.harness_reachable_status.keys():
            if self.harness_reachable_status[harness] == HarnessReachableStatus.COMPILER_UNREACHABLE:
                continue
            elif harness in unreachable_harnesses:
                self.harness_reachable_status[harness] = HarnessReachableStatus.UNREACHABLE
            else:
                self.harness_reachable_status[harness] = HarnessReachableStatus.UNSET
            self.apply_harness_deprioritization(harness)

    def process_directed_fuzzer_response(self, input_message: DirectedFuzzerResponse):
        with self.directed_epoch_cond:
            if input_message.cmd == DF_RUN:
                task = self.directed_task_scheduler.find_task_by_fuzzer_session_id(input_message.fuzzer_session_id)
                if task:
                    if task.location not in self.location_to_harness_to_reachability:
                        self.location_to_harness_to_reachability[task.location] = {}
                    if input_message.status == DF_SUCCESS:
                        # Set this harness as reachable if not already set by other source (SARIF)
                        if (self.location_to_harness_to_reachability[task.location].get(task.harness_id, LocationHarnessReachableStatus.UNSET)
                            != LocationHarnessReachableStatus.UNREACHABLE):
                            self.location_to_harness_to_reachability[task.location][task.harness_id] = LocationHarnessReachableStatus.REACHABLE
                        self.directed_task_scheduler.update_task_state(task, DirectedTaskState.RUNNING)
                    # this could be like compilation failure or target unreachable
                    elif input_message.status == DF_FAILURE:
                        if "no path to the target" in input_message.aux:
                            self.location_to_harness_to_reachability[task.location][task.harness_id] = LocationHarnessReachableStatus.UNREACHABLE
                        elif "target location not found in codebase" in input_message.aux:
                            self.location_to_harness_to_reachability[task.location][task.harness_id] = LocationHarnessReachableStatus.NOTFOUND
                        else:
                            self.location_to_harness_to_reachability[task.location][task.harness_id] = LocationHarnessReachableStatus.UNSET
                        self.directed_task_scheduler.remove_directed_task(task)
                        self.directed_epoch_cond.notify()
                    self.__update_location_reachability()
                else:
                    logger.error(f"Could not find task {input_message.fuzzer_session_id}")
            # only care about run responses, ignore stop responses

        with self.lock:
            self.apply_harness_deprioritization(input_message.harness_id)

    def process_optimized_build(self, build_info):
        def md5sum(binary_path) -> str:
            checksum = subprocess.run(f"md5sum {binary_path} | cut -f1 -d' '", shell=True, capture_output=True, text=True).stdout
            logging.info(f"Checksum of {binary_path} is {checksum}")
            return checksum
        
        if self.other_optimized_build:
            duplicate_harnesses = []
            for harness_id, harness_path in build_info.harnesses.items():
                if harness_id not in self.other_optimized_build.harnesses:
                    continue
                other_harness_path = self.other_optimized_build.harnesses[harness_id]
                if md5sum(harness_path) == md5sum(other_harness_path):
                    duplicate_harnesses.append(harness_id)
                self.harness_reachable_status[harness_id] = HarnessReachableStatus.UNSET # just in case
            logging.info(f"Duplicate harnesses {duplicate_harnesses}")
            if set(duplicate_harnesses) == set(build_info.harnesses.keys()):
                logging.info("We would be trying to deprioritize all harnesses! Ignoring results.")
            else:
                for harness in duplicate_harnesses:
                    self.harness_reachable_status[harness] = HarnessReachableStatus.COMPILER_UNREACHABLE
                    self.apply_harness_deprioritization(harness)
            self.done_optimized_builds = True
        else:
            self.other_optimized_build = build_info

    # can only be called after cp_config, osv_analyzer_result, harness_to_fuzzer_binaries is properly set
    def construct_fuzzer_run_request(self, harness_name: str, fuzzer_mode, core_num: int) -> FuzzerRunRequest | None:
        # fuzzer_mode: LIBAFL, LIBFUZZER
        for nonce, build_info in self.builds.items():
            if build_info.status == BuildStatus.SUCCESS and build_info.mode == fuzzer_mode:
                if harness_name not in build_info.harnesses:
                    logger.error(f"Harness {harness_name} not found in build {self.libfuzzer_nonce}")
                    return None

                node_idx, cores = self.core_allocator.allocate_cores(core_num)
                logger.info(f"Using node {node_idx} for fuzzer run request")
                run_request = FuzzerRunRequest(
                    corpus_files = self.osv_analyzer_result.corpus_files,
                    dictionary_files = self.osv_analyzer_result.dictionary_files,
                    nonce = nonce,
                    output_path = f'/crs_scratch/{nonce}',
                    binary_paths = self.harness_to_fuzzer_binaries[harness_name],
                    harness_id = harness_name,
                    node_idx = node_idx,
                    cores = cores,
                    cp_name = build_info.cp_name,
                    oss_fuzz_path = self.cp_config.oss_fuzz_path,
                    cp_src_path = self.cp_config.cp_src_path,
                    cp_mount_path = self.cp_mount_path,
                    task_id = self.cp_config.task_id,
                    mode = mode_to_string(fuzzer_mode),
                    epoch_expiry = int(self.epoch_expiry),
                )
                return run_request

    def construct_directed_fuzzer_request(self, task: DirectedTask, metadata: DirectedTaskMetadata) -> DirectedFuzzerRequest | None:
        harness_id = task.harness_id
        logger.info(f"[directed] constructing request for {harness_id}")
        if harness_id not in self.directed_built_harnesses:
            logger.error(f"[directed] {harness_id} not in existing build info: {self.directed_built_harnesses}")
            return None

        harness_path = self.directed_info.harnesses[harness_id]
        corpus_files = self.osv_analyzer_result.corpus_files if self.osv_analyzer_result else None
        dictionary_files = self.osv_analyzer_result.dictionary_files if self.osv_analyzer_result else None

        return DirectedFuzzerRequest(
            cmd = DF_RUN,
            nonce = self.directed_nonce,
            artifacts_path = str(Path(harness_path).parent), # slight modification of what builder_impl returns
            harness_id = task.harness_id,
            location = task.location,
            node_idx = metadata.node_idx,
            cores = [metadata.cpu_idx],
            cp_name = self.directed_info.cp_name,
            cp_src_path = self.cp_config.cp_src_path,
            cp_mount_path = self.cp_mount_path,
            output_path = f'/crs_scratch/{self.directed_nonce}',
            task_id = self.cp_config.task_id, # NOTE not used in fuzzer manager?
            sarif_id = task.sarif_id,
            fuzzer_session_id = task.fuzzer_session_id,
            corpus_files = corpus_files,
            dictionary_files = dictionary_files,
        )
        
    def construct_directed_stop_request(self, task: DirectedTask, metadata: DirectedTaskMetadata) -> DirectedFuzzerRequest:
        return DirectedFuzzerRequest(
            cmd = DF_STOP,
            nonce = self.directed_nonce,
            fuzzer_session_id = task.fuzzer_session_id,
            node_idx = metadata.node_idx,
        )
            
    def request_deepgen_launch(self) -> bool:
        if not (self.file_ops_processed and self.config_gen_processed):
            return True

        # this message will be broadcasted to all nodes
        cores = config.CORES_FOR_DEEPGEN
        if len(cores) == 0:
            logger.error("No cores available for deepgen launch")
            return False


        logger.info(f"Right before deepgen launch! {self.cp_mount_path}")
        msg= DeepGenRequest(
            msg_type=START,
            cores=cores,
            cp_name=self.cp_config.cp_name,
            oss_fuzz_path=self.cp_config.oss_fuzz_path,
            cp_src_path=self.cp_config.cp_src_path,
            mode=self.cp_config.mode,
            cp_mount_path=self.cp_mount_path,
        ) 
        logger.info(f"Requesting deepgen launch: {protobuf_repr(msg)}")
        producer = Producer(KAFKA_SERVER_ADDR, DEEPGEN_REQUEST_TOPIC)
        producer.send_message(msg)
        return True

    def register_builds(self):
        if self.osv_analyzer_result is None:
            return

        logging.info("Made it past osv_analyzer_results")
        # self.builds has one entry per build mode, and each entry can have multiple harnesses.
        # But here, we need a data structure with one entry per harness, where each entry represents multiple build modes.
        build_modes_processed = set()
        for nonce, build_info in self.builds.items():
            if build_info.status == BuildStatus.SUCCESS:
                build_modes_processed.add(build_info.mode)
                for harness_name, harness_path in build_info.harnesses.items():
                    if harness_name not in self.harness_to_fuzzer_binaries:
                        self.harness_to_fuzzer_binaries[harness_name] = FuzzerBinaries()

                    if build_info.mode == LIBAFL:
                        self.harness_to_fuzzer_binaries[harness_name].libafl = harness_path
                    elif build_info.mode == SINGLE_INPUT:
                        self.harness_to_fuzzer_binaries[harness_name].single_input = harness_path
                    elif build_info.mode == SINGLE_INPUT_SBCC:
                        self.harness_to_fuzzer_binaries[harness_name].single_input_sbcc = harness_path
                    elif build_info.mode == LIBFUZZER:
                        self.harness_to_fuzzer_binaries[harness_name].libfuzzer = harness_path
                    elif build_info.mode == LIBFUZZER_SBCC:
                        self.harness_to_fuzzer_binaries[harness_name].libfuzzer_sbcc = harness_path
                    elif build_info.mode == AFL:
                        self.harness_to_fuzzer_binaries[harness_name].afl = harness_path
                    elif build_info.mode == HONGGFUZZ:
                        self.harness_to_fuzzer_binaries[harness_name].honggfuzz = harness_path
                    elif build_info.mode == UBSAN:
                        self.harness_to_fuzzer_binaries[harness_name].ubsan = harness_path
                    elif build_info.mode == MSAN:
                        self.harness_to_fuzzer_binaries[harness_name].msan = harness_path
                    elif build_info.mode == SANS:
                        self.harness_to_fuzzer_binaries[harness_name].sans = harness_path
            elif build_info.status == BuildStatus.FAILED:
                build_modes_processed.add(build_info.mode)

        override_fuzzer = os.environ.get('OVERRIDE_FUZZER')
        logging.info(f"build modes processed {build_modes_processed}")
        logging.info(f"general fuzzing modes {config.GENERAL_FUZZING_MODES}")

        optimized_done = (not self.delta_mode) or self.done_optimized_builds

        if (( build_modes_processed >= set(config.GENERAL_FUZZING_MODES) 
              and self.current_epoch == EPOCH_UNSET 
              and optimized_done ) 
             or self.timeout_flag ):

            logger.info(f"Harnesses: {list(self.harness_to_fuzzer_binaries.keys())}")
            self.built_harnesses = list(self.harness_to_fuzzer_binaries.keys())
            initial_task_list = []

            built_harnesses = set(self.built_harnesses)
            hardcoded_harnesses = os.environ.get('OVERRIDE_HARNESSES')
            if hardcoded_harnesses:
                # Parse comma-separated harness IDs
                harness_ids = set(h.strip() for h in hardcoded_harnesses.split(','))
                built_harnesses &= harness_ids

            for harness_name in built_harnesses:
                # NOTE debugging override
                if override_fuzzer:
                    task_type = TaskType.from_mode(override_fuzzer)
                    self.task_scheduler.register_new_task(Task(task_type, harness_name))
                    continue

                # Initialize harness reachability status to 0 (unset)
                # We don't override already set status, optimized reachability could already set it
                if harness_name not in self.harness_reachable_status:
                    self.harness_reachable_status[harness_name] = HarnessReachableStatus.UNSET

                # Register new task
                task = self.bootstrap_task_from_harness(harness_name)

                # Also register other sanitizers
                sanitizer_tasks = []
                if self.harness_to_fuzzer_binaries[harness_name].ubsan:
                    sanitizer_tasks.append(Task(TaskType.UBSAN, harness_name))
                if self.harness_to_fuzzer_binaries[harness_name].msan:
                    sanitizer_tasks.append(Task(TaskType.MSAN, harness_name))
                if self.harness_to_fuzzer_binaries[harness_name].sans:
                    sanitizer_tasks.append(Task(TaskType.SANS, harness_name))

                # We'll let tasks be registered, but deprioritize if set and not run in initial_task_list
                if self.harness_reachable_status[harness_name].is_unreachable():
                    self.apply_harness_deprioritization(harness_name)
                    continue
                    
                # Add it to be run initially by putting at end (extendleft queue's to front one-by-one)
                initial_task_list.append(task)

                for new_task in sanitizer_tasks:
                    self.task_scheduler.register_new_task(new_task) # done in case self.tasks gets finicky
                    self.task_scheduler.update_task_weight(new_task, 0)
                    # Add to be run later by putting it at beginning
                    initial_task_list.insert(0, new_task)


            # Also maybe deprioritize based on SARIF call graph (if came early)
            self.prepare_sarif_reachability_deprioritization_if_needed()

            # start with predetermined list of tasks
            logging.info(f"Initial task list {initial_task_list}")
            self.task_scheduler.push_tasks_immediately(initial_task_list)

            # Send custom fuzzer run request before the first epoch starts
            cores = self.core_allocator.allocate_core_for_one_node(node_idx=0, core_num=1)
            custom_fuzzer_producer = Producer(KAFKA_SERVER_ADDR, CUSTOM_FUZZER_RUN_REQUEST_TOPIC)
            m = CustomFuzzerRunRequest(
                project_names = self.osv_analyzer_result.project_names,
                cp_name = self.cp_config.cp_name,
                cp_src_path = self.cp_config.cp_src_path,
                oss_fuzz_path = self.cp_config.oss_fuzz_path,
                node_idx = 0,
                cores = cores,
            )
            logger.info(f"Sending custom fuzzer run request: {protobuf_repr(m)}")
            custom_fuzzer_producer.send_message(m)
            
            # start epoch here because harness_builder -> osv_analyzer is a possible trigger condition
            logger.info("Starting epoch thread")
            self.current_epoch = 0
            self.epoch_thread = Thread(target=self.loop_epoch)
            self.epoch_thread.start()

    def __transition_fuzzer_mode(self, from_mode: str, to_mode: str, harness_id: str, cores: list[int], launch: bool) -> None:
        """Helper method to transition from one fuzzer mode to another.
        
        Args:
            from_mode: The current mode that failed (e.g. "libafl", "afl")
            to_mode: The mode to transition to (e.g. "afl", "libfuzzer")
            harness_id: The harness ID to transition
            cores: The cores to use for the new fuzzer
        """
        from_task_type = TaskType.from_mode(from_mode)
        to_task_type = TaskType.from_mode(to_mode)
        # request_mode = string_to_mode(to_mode)
        
        logger.warning(f"{from_mode} failed to run, requesting again with {to_mode}")
        weight = self.task_scheduler.remove_task(Task(from_task_type, harness_id))
        new_task = Task(to_task_type, harness_id)
        self.task_scheduler.register_new_task(new_task, weight)
        if launch:
            run_request = self.task_to_run_request(new_task)
            # run_request = self.construct_fuzzer_run_request(harness_id, request_mode, NODE_CPU_CORES)
            self.fuzzer_run_request_producer.send_message(run_request)
            self.pending_fuzzer_requests += 1

    def process_fuzzer_run_response(self, input_message: FuzzerRunResponse):
        with self.lock:
            cores = [int(core) for core in input_message.cores]
            if input_message.status == FAILURE:
                self.core_allocator.free_cores(input_message.node_idx, cores)

                # Do not transition if we are backup fuzzer and died from insufficient timeout attempt
                should_transition = True
                # Do not launch if we timed out. Timeout only happens close to end of epoch
                launch = input_message.stage != FUZZER_INIT
                
                if input_message.stage == FUZZER_INIT:
                    self.pending_fuzzer_requests -= 1
                    # if there was not enough time left (i.e. rt error -> timeout),
                    # and we're trying one of the backup fuzzers,
                    # then don't transition to another one.
                    # Also, libafl cond works because in either case (first fuzzer, or after libfuzzer),
                    # libafl only starts at the start of the epoch
                    if input_message.time_left < int(config.FUZZER_STARTUP_ALLOWANCE_RATIO * config.EPOCH_DURATION) and input_message.mode != "libafl":
                        should_transition = False
                        logger.info(f"There wasn't enough time left {input_message.time_left}s when timeout happened, so we don't transition fuzzer just yet")
                elif input_message.stage == FUZZER_RUN:
                    _fuzzer_session_info = self.fuzzer_sessions.pop(input_message.fuzzer_session_id)

                if should_transition:
                    harness_id = input_message.harness_id
                    task_weight = sum(self.task_scheduler.tasks.values())
                    # Handle fallback based on mode
                    if input_message.mode == "libafl":
                        # libafl failed to run, so request again with afl, keep deepgen running
                        self.__transition_fuzzer_mode("libafl", "afl", input_message.harness_id, cores, launch)
                    elif input_message.mode == "afl":
                        # afl failed to run, so request again with libfuzzer, keep deepgen running
                        self.__transition_fuzzer_mode("afl", "libfuzzer", input_message.harness_id, cores, launch)
                    elif task_weight > NODE_NUM:
                        # NOTE currently libfuzzer will never return FUZZER_RUN error response
                        logger.error(f"Disabling harness: libfuzzer failed to run {input_message.harness_id}, and {task_weight} tasks > {NODE_NUM} nodes")
                        _weight = self.task_scheduler.remove_task(Task(TaskType.LIBFUZZER, input_message.harness_id))
                    else:
                        self.__transition_fuzzer_mode("libfuzzer", "libafl", input_message.harness_id, cores, launch)

                logger.info("Freed cores since the fuzzer failed to run")

            else:
                fuzzer_task = Task(TaskType.from_mode(input_message.mode), input_message.harness_id)
                fuzzer_session_info = FuzzerSessionInfo(
                    fuzzer_task=fuzzer_task,
                    node_idx=int(input_message.node_idx),
                    cores=cores,
                )
                self.fuzzer_sessions[input_message.fuzzer_session_id] = fuzzer_session_info
                self.pending_fuzzer_requests -= 1
                logger.info(f"Fuzzer session for {input_message.harness_id} has started")
            
            if self.pending_fuzzer_requests == 0:
                self.no_pending_fuzzer_requests_condition.notify_all()
            return []

    def process_fuzzer_stop_response(self, input_message: FuzzerStopResponse):
        with self.lock:
            if input_message.status == SUCCESS:
                fuzzer_session_info = self.fuzzer_sessions.pop(input_message.fuzzer_session_id)
                self.core_allocator.free_cores(fuzzer_session_info.node_idx, fuzzer_session_info.cores)
                self.pending_fuzzer_requests -= 1 
                if self.pending_fuzzer_requests == 0:
                    self.no_pending_fuzzer_requests_condition.notify_all()
            return []

    # separate from the catch-all build hook because there's not dep on osv analyzer
    def prepare_directed_fuzzer_requests_if_needed(self):
        # state: either sarif request arrives and we're not finished building,
        #        or we're finished building and waiting on sarif

        if self.osv_analyzer_result is None:
            logger.info("[directed] no OSV Analyzer results yet")
            return

        # find the build_info for the directed build
        if not self.directed_info:
            for nonce, build_info in self.builds.items():
                if build_info.mode != DIRECTED:
                    continue
                if build_info.status != BuildStatus.SUCCESS:
                    continue
                self.directed_info = build_info
                self.directed_nonce = nonce
                break
            else:
                logger.info("[directed] no directed fuzzer build artifacts")
                return

        optimized_done = (not self.delta_mode) or self.done_optimized_builds
        if not optimized_done:
            logger.info("[directed] no optimized build prioritization results yet")
            return

        self.directed_built_harnesses = list(self.directed_info.harnesses.keys())
        if self.delta_mode:
            to_remove = set()
            for harness, status in self.harness_reachable_status.items():
                if status == HarnessReachableStatus.COMPILER_UNREACHABLE:
                    to_remove.add(harness)

            if to_remove < set(self.directed_built_harnesses):
                for harness in to_remove:
                    try:
                        self.directed_built_harnesses.remove(harness)
                    except ValueError:
                        logger.error(f"Couldn't find harness {harness} in directed built harnesses {self.directed_built_harnesses}")


        # convert locations into tasks, need harnesses for this
        for location in self.pending_directed_locations:
            for harness_id in self.directed_built_harnesses:
                task = DirectedTask(
                    type_ = TaskType.DIRECTED_FUZZER,
                    location = location,
                    harness_id = harness_id,
                    sarif_id = None,
                    fuzzer_session_id = str(uuid.uuid4()),
                )
                logger.info(f"Converting location into task {task}")
                self.pending_directed_tasks.append(task)
        self.pending_directed_locations.clear()

        # move pending tasks to scheduler
        sarif_tasks = []
        non_sarif_tasks = []
        for task in self.pending_directed_tasks:
            if task.sarif_id:
                sarif_tasks.append(task)
            else:
                non_sarif_tasks.append(task)

        with self.directed_epoch_cond: # re-entrant, but fine
            self.directed_task_scheduler.queue_tasks(non_sarif_tasks)
            self.directed_task_scheduler.queue_tasks_immediately(sarif_tasks)
            if len(sarif_tasks) > 0:
                stop_tasks = self.directed_task_scheduler.evict_tasks(len(sarif_tasks))
                logger.info("Stopping some directed tasks because we have new sarif tasks")
                for task, metadata in stop_tasks:
                    logger.info(f"Stopping {task}")
                    self.directed_fuzzer_producer.send_message(self.construct_directed_stop_request(task, metadata))
            self.directed_epoch_cond.notify()
            self.pending_directed_tasks.clear()
                
        # set up epoch loop if not yet initialized
        if self.current_directed_epoch == EPOCH_UNSET:
            self.current_directed_epoch = 0
            self.directed_epoch_thread = Thread(target=self.loop_directed_epoch)
            self.directed_epoch_thread.start()
    
    def prepare_sarif_reachability_deprioritization_if_needed(self):
        if self.built_harnesses and self.received_reachability_results:
            self.__update_location_reachability()
            
    def process_sarif_harness_reachability(self, input_message: LibSarifHarnessReachability):
        with self.lock:
            location_map = input_message.location_harnesses_disabled
            for location in location_map.keys():
                if location not in self.location_to_harness_to_reachability:
                    self.location_to_harness_to_reachability[location] = {}
                disabled_harnesses = location_map[location].values
                for harness in disabled_harnesses:
                    self.location_to_harness_to_reachability[location][harness] = LocationHarnessReachableStatus.UNREACHABLE
            
            logger.info(f"Location reachabilities set {self.location_to_harness_to_reachability}")
            self.received_reachability_results = True
            self.prepare_sarif_reachability_deprioritization_if_needed()

    def task_to_run_request(self, task: Task) -> Message:
        if task.type_ == TaskType.AFL:
            # by giving NODE_CPU_CORES, we are asking the fuzzer to use all the cores left in one node
            return self.construct_fuzzer_run_request(task.harness_id, AFL, NODE_CPU_CORES)
        elif task.type_ == TaskType.LIBAFL:
            # by giving NODE_CPU_CORES, we are asking the fuzzer to use all the cores left in one node
            return self.construct_fuzzer_run_request(task.harness_id, LIBAFL, NODE_CPU_CORES)
        elif task.type_ == TaskType.LIBFUZZER:
            return self.construct_fuzzer_run_request(task.harness_id, LIBFUZZER, NODE_CPU_CORES)
        elif task.type_ == TaskType.UBSAN:
            return self.construct_fuzzer_run_request(task.harness_id, UBSAN, NODE_CPU_CORES)
        elif task.type_ == TaskType.MSAN:
            return self.construct_fuzzer_run_request(task.harness_id, MSAN, NODE_CPU_CORES)
        elif task.type_ == TaskType.SANS:
            return self.construct_fuzzer_run_request(task.harness_id, SANS, NODE_CPU_CORES)
        elif task.type_ == TaskType.DIRECTED_FUZZER:
            pass
        elif task.type_ == TaskType.CUSTOM_FUZZER:
            pass

    def bootstrap_task_from_harness(self, harness_name) -> Task:
        # Current priority: LibAFL > AFL > LibFuzzer
        if self.harness_to_fuzzer_binaries[harness_name].libafl:
            new_task = Task(TaskType.LIBAFL, harness_name)
        elif self.harness_to_fuzzer_binaries[harness_name].afl:
            new_task = Task(TaskType.AFL, harness_name)
        else:
            new_task = Task(TaskType.LIBFUZZER, harness_name)

        self.task_scheduler.register_new_task(new_task)
        return new_task
        
    # NOTE only apply this after changing harness_id's reachable status
    def apply_harness_deprioritization_inner(self, harness_id):
        # Update task weights based on reachability status
        reachability = self.harness_reachable_status.get(harness_id, HarnessReachableStatus.UNSET)
        notification: HarnessPrioritization | None = None

        if reachability.is_unreachable():
            # disable all fuzzing (tasks) for this harness
            for type_ in TaskType.general_fuzzing_modes():
                task = Task(type_ = type_, harness_id = harness_id)
                logger.info(f"Found no path to target, unreachable, deprioritizing {harness_id}")
                self.task_scheduler.remove_task(task)
            notification = HarnessPrioritization(enable=False, harness_id=harness_id)

        if notification:
            self.harness_prioritization_producer.send_message(notification)

    def apply_harness_deprioritization(self, harness_id):
        logger.info(f"Might deprioritize {harness_id}. Dumping reachable status mapping {self.harness_reachable_status}")
        
        # Wait until no fuzzer requests are pending
        with self.no_pending_fuzzer_requests_condition:
            while self.pending_fuzzer_requests > 0:
                self.no_pending_fuzzer_requests_condition.wait()

        # All harnesses are marked unreachable! ignore these results and schedule everything.
        status_list = [status.is_unreachable() for status in self.harness_reachable_status.values()]
        if status_list and all(status_list):
            logging.warning("All harnesses are marked as unreachable! We will enable all harnesses for the time being.")
            self.harness_reachable_ignore = True
            for harness_name in self.built_harnesses:
                self.bootstrap_task_from_harness(harness_name)
                notification = HarnessPrioritization(enable=True, harness_id=harness_name)
                self.harness_prioritization_producer.send_message(notification)
            self.task_scheduler.apply_task_weights_immediately()
            return

        # Previously all harnesses were marked as unreachable. Apply deprioritization to all harnesses again.
        if self.harness_reachable_ignore:
            logging.info("All harnesses were previously marked as unreachable. We will apply deprioritization to all harnesses.")
            self.harness_reachable_ignore = False
            for harness_name in self.harness_reachable_status.keys():
                self.apply_harness_deprioritization_inner(harness_name)
            return
        
        # Normal case, just apply to single harness
        self.apply_harness_deprioritization_inner(harness_id)

    def loop_epoch(self, epoch_duration: int=config.EPOCH_DURATION):
        while True:
            this_epoch_duration = epoch_duration
            if self.cp_config.deadline - time.time() < epoch_duration * 2:
                this_epoch_duration = self.cp_config.deadline - time.time()
            self.__run_epoch(this_epoch_duration)

    def __run_epoch(self, epoch_duration: int=config.EPOCH_DURATION):
        logger.info(f"=== EPOCH {self.current_epoch} ===")
        self.task_scheduler.log_popped_tasks()
        
        # Log task weights by task type and harness
        logger.info("Current Task Weights:")
        for task, weight in self.task_scheduler.tasks.items():
            logger.info(f"  {task.type_.name:<10} {task.harness_id:<15} weight: {weight}")

        # Log current queue state
        logger.info("Current Queue State:")
        for idx, task in enumerate(self.task_scheduler.queue):
            logger.info(f"  {idx+1:>3}. {task.type_.name:<10} {task.harness_id:<15}")
        if not self.task_scheduler.queue:
            logger.info("  Queue is empty")

        self.epoch_expiry = time.time() + config.EPOCH_DURATION
        # 1. send requests for epoch start
        if not self.continue_epoch:
            logger.info("Sending requests for epoch start")
            self.__epoch_start()
        else:
            logger.info("Continue off from previous session, skipping sending requests for epoch start")
        epoch_start_weights = self.task_scheduler.snapshot_weights()
        epoch_start_task_queue = self.task_scheduler.queue.copy()
        # 2. wait for the timer to end or the event to be set
        self.epoch_event.clear()
        triggered = self.epoch_event.wait(timeout=epoch_duration)
        if triggered:
            logger.info("Epoch end was manually triggered")
        else:
            logger.info("Epoch has ended by timeout")
        # 3. evaluate the last epoch and update task weights
        logger.info("Evaluating the last epoch")
        self.__evaluate_last_epoch()
        # 4. update task weights
        logger.info("Updating task weights")
        self.__update_task_weights()
        # 5. check we can just continue this epoch
        self.continue_epoch = self.__epoch_end(epoch_start_weights, epoch_start_task_queue)
        # 6. get ready for the next epoch
        logger.info("Getting ready for the next epoch")
        self.current_epoch += 1

    def __epoch_start(self):
        # all requests are sent during epoch start
        with self.no_pending_fuzzer_requests_condition:
            while self.pending_fuzzer_requests > 0:
                logger.info(f"Waiting for {self.pending_fuzzer_requests} pending fuzzer requests to be processed")
                self.no_pending_fuzzer_requests_condition.wait()

            with self.lock:
                fuzzer_stop_requests = []
                tasks = self.task_scheduler.get_tasks_for_epoch()

                # let's find sessions that are not in the tasks list and only stop them and keep the rest
                session_ids_to_keep = []
                for session_id in self.fuzzer_sessions:
                    if session_id not in session_ids_to_keep and self.fuzzer_sessions[session_id].fuzzer_task in tasks:
                        session_ids_to_keep.append(session_id)
                        tasks.remove(self.fuzzer_sessions[session_id].fuzzer_task)

                for session_id, session_info in self.fuzzer_sessions.items():
                    if session_id not in session_ids_to_keep:
                        fuzzer_stop_request = FuzzerStopRequest(
                            fuzzer_session_id=session_id,
                            node_idx=session_info.node_idx,
                            harness_id = session_info.fuzzer_task.harness_id,
                        )
                        fuzzer_stop_requests.append(fuzzer_stop_request)
                
                if fuzzer_stop_requests:
                    logger.info(f"Send {len(fuzzer_stop_requests)} fuzzer stop requests")
                    for m in fuzzer_stop_requests:
                        logger.info(f'Sending message: {protobuf_repr(m)}')
                        self.fuzzer_stop_request_producer.send_message(m)
                        self.pending_fuzzer_requests += 1
                
        with self.no_pending_fuzzer_requests_condition:
            while self.pending_fuzzer_requests > 0:
                logger.info(f"Waiting for {self.pending_fuzzer_requests} pending fuzzer requests to be processed")
                self.no_pending_fuzzer_requests_condition.wait()

            with self.lock:
                fuzzer_run_requests = []
                for task in tasks:
                    if task.type_ in TaskType.general_fuzzing_modes():
                        logger.info(f"Task {task.type_} {task.harness_id}")
                        fuzzer_run_request = self.task_to_run_request(task)
                        fuzzer_run_requests.append(fuzzer_run_request)
                if fuzzer_run_requests:
                    logger.info(f"Send {len(fuzzer_run_requests)} fuzzer run requests")
                    for m in fuzzer_run_requests:
                        logger.info(f'Sending message: {protobuf_repr(m)}')
                        self.fuzzer_run_request_producer.send_message(m)
                        self.pending_fuzzer_requests += 1
                
    def __evaluate_last_epoch(self):
        pass

    def __update_task_weights(self):
        pass

    def __epoch_end(self, epoch_start_weights, epoch_start_task_queue):
        # check if we can just continue this epoch
        # no weight change + no new task (reachability analysis)
        epoch_end_weights = self.task_scheduler.snapshot_weights()
        if epoch_start_weights != epoch_end_weights:
            logger.info("Weight change, new epoch should start")
            return False
        # no task queue change (reachability analysis)
        if epoch_start_task_queue != self.task_scheduler.queue:
            logger.info("Task queue change, new epoch should start")
            return False
        # no complete harness starvation
        if len(self.task_scheduler.get_starved_tasks()) > 0:
            logger.info("Harness starvation, new epoch should start")
            return False
        # check if the actual run of the harnesses are similar to the weights
        if self.task_scheduler.check_prioritization() > len(self.built_harnesses) / 8:
            logger.info("Some harnesses should be prioritized more, new epoch should start")
            return False
        return True

    def loop_directed_epoch(self, epoch_duration: int=config.DIRECTED_EPOCH_DURATION):
        try:
            while True:
                this_epoch_duration = epoch_duration
                if self.cp_config.deadline - time.time() < epoch_duration * 2:
                    this_epoch_duration = self.cp_config.deadline - time.time()
                    if this_epoch_duration <= 0:
                        break
                self.__run_directed_epoch(this_epoch_duration, continue_previous_epoch=False)
        except: # try not to kill main controller thread
            pass

    def __run_directed_epoch(self, epoch_duration: int=config.DIRECTED_EPOCH_DURATION, continue_previous_epoch: bool=False):
        with self.directed_epoch_cond:
            logger.info(f"=== DIRECTED EPOCH {self.current_directed_epoch} ===")
            current_time = time.time()

            new_tasks = self.directed_task_scheduler.populate_taskset()
            for task, metadata in new_tasks:
                message = self.construct_directed_fuzzer_request(task, metadata)
                if message:
                    self.directed_fuzzer_producer.send_message(message)

            # wait for signal or timeout
            self.directed_epoch_cond.wait(timeout=epoch_duration)

            self.directed_task_scheduler.update_taskset_time_elapsed(int(time.time() - current_time))

            removed_tasks = self.directed_task_scheduler.rotate_tasks()
            for task, metadata in removed_tasks:
                message = self.construct_directed_stop_request(task, metadata)
                self.directed_fuzzer_producer.send_message(message)

            self.current_directed_epoch += 1
