import subprocess
import os
from python_on_whales import docker, DockerException
from typing import Optional, Tuple
import logging
from threading import RLock
from enum import Enum
from pathlib import Path
import yaml
import tarfile
import zstandard as zstd
import time
from google.protobuf.message import Message

from libatlantis.protobuf import (
    CustomFuzzerRunRequest,
    CustomFuzzerRunResponse,
    CustomFuzzerStopRequest,
    BuildRequestResponse,
    SUCCESS,
    FAILURE,
    mode_to_string,
)
from libatlantis.constants import CRS_SCRATCH_DIR

from custom_fuzzer_utils.run import (
    get_config,
    start_container,
    build_fuzzer,
    run_fuzzer,
    stop_container,
    get_container_name,
)
from . import config

DEBUG = os.getenv("DEBUG", False)

logger = logging.getLogger(__name__)


def run(cmd, show_stdout: bool = False, show_stderr: bool = True):
    stdout = subprocess.STDOUT if show_stdout else subprocess.PIPE
    stderr = subprocess.STDOUT if show_stderr else subprocess.PIPE
    logger.info(f"Running command: {cmd}")
    subprocess.run(cmd, check=True, stdout=stdout, stderr=stderr)

def rsync(src: Path, dst: Path):
    if src.is_dir():
        src = f"{src}/."
    run(["rsync", "-a", str(src), str(dst)])

def load_image(tar_path: Path) -> list[str]:
    return docker.load(tar_path)

def docker_run_cmd(
    image_name,
    container_name,
    docker_cmd: str,
    env_vars: dict[str, str],
    volume_mounts: dict[str, str],
    cores: list[int],
):
    cmd = "docker run --privileged"

    cmd += f" --name {container_name}"
    cmd += f" --cpuset-cpus {','.join(str(core) for core in cores)}"
    for key, value in env_vars.items():
        cmd += f" -e {key.upper()}={value}"
    for volume_mount, host_path in volume_mounts.items():
        cmd += f" -v {host_path}:{volume_mount}"
    cmd += f" {image_name}"
    cmd += f" {docker_cmd}"
    return cmd

def docker_exec_cmd(container_name, docker_cmd: str):
    return f"docker exec {container_name} {docker_cmd}"

def divide_cores(cores: list[int], n: int):
    k, m = divmod(len(cores), n)
    return [cores[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)] for i in range(n)]

def extract_tar_zst(src_path: Path, dst_dir: Path):
    with open(src_path, "rb") as compressed:
        dctx = zstd.ZstdDecompressor()
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                tar.extractall(path=dst_dir)


class CustomFuzzerSessionStatus(Enum):
    RUNNING = 0
    STOPPED = 1
    ERROR = 2
    ENDED = 3
    BUILDING = 4


class CustomFuzzerSession:

    container_name: str
    image_name: str

    def __init__(
        self,
        process: subprocess.Popen,
        container_name: str,
        image_name: str,
        crashes_path: Path,
        corpus_path: Path,
        src_path: Path,
    ):
        self.process = process
        self.container_name = container_name
        self.image_name = image_name
        self.crashes_path = crashes_path
        self.corpus_path = corpus_path
        self.src_path = src_path

    # TODO: better way needed
    def check_fuzzer_successful(self):
        status = self.process.poll()
        if status is None:
            return True
        else:
            return status == 0

    def status(self) -> CustomFuzzerSessionStatus:
        pass

    def build(self):  # setup, build
        pass

    def run(self):  # start fuzzing
        pass

    def stop(self):  # graceful
        pass

    def kill(self):
        pass


class CustomFuzzerContext:

    sessions: dict[str, CustomFuzzerSession]
    core_usage: dict[str, list[int]]  # session_id -> core_idx list
    node_idx: int

    def __init__(self):
        self.sessions = {}
        self.core_usage = {}
        self.node_idx = 0  # os.environ.get("NODE_IDX", 0) # TODO: currently per harness
        self.lock = RLock()
        self.osv_analyzer_result = None
        self.fuzzer_image_tars = []
        self.fuzzer_images = []
        self.available_fuzzers = {}
        self.harnesses = {}
        self.__load_fuzzer_yaml()
        self.__extract_fuzzers()

    def info(self, msg: str):
        logger.info(f"[Custom Fuzzer] {msg}")

    def error(self, msg: str):
        logger.error(f"[Custom Fuzzer] {msg}")

    def add_session(self, fuzz_session: CustomFuzzerSession, cores: list[int]):
        with self.lock:
            session_id = fuzz_session.container_name
            logger.info(f"Added session {session_id}")
            self.sessions[session_id] = fuzz_session
            self.core_usage[session_id] = cores
            return session_id

    def remove_session(self, session_id: str) -> list[int]:
        with self.lock:
            fuzzer_session = self.sessions.get(session_id)
            if fuzzer_session:
                # TODO: different logic?
                if fuzzer_session.status == CustomFuzzerSessionStatus.STOPPED:
                    logger.info(
                        f"Fuzzer {fuzzer_session.harness_id} {session_id} is already stopped"
                    )
                else:
                    logger.info(
                        f"Stopping fuzzer {fuzzer_session.harness_id} {session_id}"
                    )
                fuzzer_session.stop()

            self.sessions.pop(session_id, None)
            cores = self.core_usage.pop(session_id, [])
            return cores

    def __load_fuzzer_yaml(self):
        self.available_fuzzers = yaml.safe_load(open(config.CUSTOM_FUZZERS_YAML_PATH))

    def __extract_fuzzers(self):
        if self.fuzzer_image_tars:
            self.info("Fuzzer images already extracted")
            return
        extract_tar_zst(config.CUSTOM_FUZZERS_TAR_PATH, config.CUSTOM_FUZZERS_PATH)
        self.fuzzer_image_tars = [
            str(f) for f in config.CUSTOM_FUZZERS_PATH.glob("*.tar")
        ]

    def __get_fuzzer_images(self, project_names: list[str]):
        logger.info(f"Getting fuzzer images for {project_names}")
        for category, category_info in self.available_fuzzers.items():
            targets = category_info.get("targets", [])
            for target in targets:
                if any(
                    project_name in target or target in project_name
                    for project_name in project_names
                ) or category in project_names:
                    return category_info.get("fuzzers", []), category
        return [], ""

    def __load_fuzzer_images(self, fuzzers: list[str]):
        self.__extract_fuzzers()
        for fuzzer in fuzzers:
            for tar in self.fuzzer_image_tars:
                logger.info(f"Loading fuzzer image {tar}")
                load_image(tar)

    def __load_fuzzer_config(self, fuzzer_name: str, category: str):
        category_config_path = config.CUSTOM_FUZZERS_PATH / f"{category}_config.yaml"
        if not category_config_path.exists():
            self.error(f"Fuzzer config for {category} not found")
            return None
        return yaml.safe_load(open(category_config_path))

    def setup_host_paths(
        self,
        fuzzer_name: str,
        target_name: str,
        cp_name: str,
        cp_src_path: Path,
        oss_fuzz_path: Path,
        shared_harness_dir: Path,
        container_name: str,
    ):
        work_dir = CRS_SCRATCH_DIR / f"custom_fuzzer/{container_name}/{target_name}/{fuzzer_name}"
        work_dir.mkdir(parents=True, exist_ok=True)
        local_src_path = work_dir / "src"
        local_src_path.mkdir(parents=True, exist_ok=True)
        local_oss_fuzz_path = work_dir / "oss-fuzz"
        local_oss_fuzz_path.mkdir(parents=True, exist_ok=True)
        local_harness_dir = work_dir / "out"
        local_harness_dir.mkdir(parents=True, exist_ok=True)

        rsync(cp_src_path, local_src_path)
        rsync(oss_fuzz_path, local_oss_fuzz_path)
        rsync(shared_harness_dir, local_harness_dir)

        return {
            "work_dir": work_dir,
            "src_path": local_src_path,
            "oss_fuzz_path": local_oss_fuzz_path,
            "harness_dir": local_harness_dir,
        }

    def process_build_request_response(
        self, input_message: BuildRequestResponse, thread_id: int
    ) -> list[Message]:
        with self.lock:
            if mode_to_string(input_message.mode) in ["afl", "libfuzzer", "libafl"]:
                self.harnesses[mode_to_string(input_message.mode)] = input_message.harnesses
        return []

    def process_custom_fuzzer_run_request(
        self, input_message: CustomFuzzerRunRequest, thread_id: int
    ) -> list[Message]:
        with self.lock:
            fuzzers, category = self.__get_fuzzer_images(
                input_message.project_names
            )
            if len(fuzzers) == 0:
                logger.error(
                    f"No fuzzers found for project names {input_message.project_names}"
                )
                return [
                    CustomFuzzerRunResponse(
                        status=FAILURE,
                        fuzzer_session_id="",
                        node_idx=input_message.node_idx,
                        cores=input_message.cores,
                        crashes_path="",
                        corpus_path="",
                        aux=f"No fuzzers found for project names {input_message.project_names}",
                    )
                ]
            self.__load_fuzzer_images(fuzzers)
            cores = input_message.cores
            #cores_per_fuzzer = divide_cores(cores, len(fuzzers))
            # TODO: actually deal with multiple fuzzers, if exists
            for fuzzer in fuzzers:
                config = get_config(fuzzer)
                if config is None:
                    logger.error(f"No fuzzer config found for fuzzer {fuzzer}")
                    continue

                host_paths = {}
                # this should not happen, because the controller should have already checked
                if "afl" not in self.harnesses or "libfuzzer" not in self.harnesses:
                    logger.error("Harnesses not found")
                    return [
                        CustomFuzzerRunResponse(
                            status=FAILURE,
                            fuzzer_session_id="",
                            node_idx=input_message.node_idx,
                            cores=cores,
                            crashes_path="",
                            corpus_path="",
                            aux="Harnesses not found",
                        )
                    ]
                container_name = get_container_name(fuzzer)
                targets = config.get("targets", [])
                for target in targets:
                    # lets just try with all supported targets
                    # FIXME: zero indexing is bad
                    if config.get("type") == "afl":
                        harness_path = Path(list(self.harnesses.get("afl").values())[0]).parent
                        host_paths = self.setup_host_paths(
                            fuzzer,
                            target,
                            input_message.cp_name,
                            Path(input_message.cp_src_path),
                            Path(input_message.oss_fuzz_path),
                            harness_path,
                            container_name,
                        )
                    else:
                        harness_path = Path(
                            list(self.harnesses.get("libfuzzer").values())[0]
                        ).parent
                        host_paths = self.setup_host_paths(
                            fuzzer,
                            target,
                            input_message.cp_name,
                            Path(input_message.cp_src_path),
                            Path(input_message.oss_fuzz_path),
                            harness_path,
                            container_name,
                        )
                    try:
                        container_name = start_container(
                            fuzzer,
                            host_paths["src_path"],
                            host_paths["work_dir"],
                            host_paths["oss_fuzz_path"],
                            host_paths["harness_dir"],
                            cores,
                            input_message.cp_name,
                            target,
                            container_name,
                        )
                    except Exception as e:
                        logger.error(f"Failed to start container for fuzzer {fuzzer}: {e}")
                        continue
                    
                    if container_name != build_fuzzer(fuzzer, container_name):
                        logger.error(f"Failed to build fuzzer {fuzzer}")
                        continue

                    handle, c_name = run_fuzzer(fuzzer, container_name, False)
                    if container_name != c_name:
                        logger.error(f"Failed to run fuzzer {fuzzer}")
                        continue

                    fuzzer_session = CustomFuzzerSession(
                        process=handle,
                        container_name=c_name,
                        image_name=fuzzer,
                        crashes_path=host_paths["work_dir"] / "crashes",
                        corpus_path=host_paths["work_dir"] / "corpus",
                        src_path=host_paths["src_path"],
                    )
                    session_id = self.add_session(fuzzer_session, cores)
                    harness_ids = list(self.harnesses.get("libfuzzer").keys())
                    if config.get("type") == "afl":
                        # FIXME: hacky way
                        return [
                            CustomFuzzerRunResponse(
                                status=SUCCESS,
                                fuzzer_session_id=session_id,
                                node_idx=input_message.node_idx,
                                cores=cores,
                                crashes_path=str(host_paths["work_dir"] / "corpus"),
                                corpus_path=str(host_paths["work_dir"] / "corpus"),
                                harness_ids=harness_ids,
                                aux="afl",
                            ) 
                        ]
                    else:
                        return [
                            CustomFuzzerRunResponse(
                                status=SUCCESS,
                                fuzzer_session_id=session_id,
                                node_idx=input_message.node_idx,
                                cores=cores,
                                crashes_path=str(host_paths["work_dir"] / "crashes"),
                                corpus_path=str(host_paths["work_dir"] / "corpus"),
                                harness_ids=harness_ids,
                                aux="",
                            )
                        ]
            return [
                CustomFuzzerRunResponse(
                    status=FAILURE,
                    fuzzer_session_id="",
                    node_idx=input_message.node_idx,
                    cores=cores,
                    aux="All fuzzers failed",
                )
            ]

    def process_custom_fuzzer_stop_request(
        self, input_message: CustomFuzzerStopRequest, thread_id: int
    ) -> list[Message]:
        return []
