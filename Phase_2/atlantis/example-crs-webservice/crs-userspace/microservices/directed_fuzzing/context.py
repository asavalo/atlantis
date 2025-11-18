import subprocess
from threading import Lock, Thread, Event
from typing import Optional
import logging
from google.protobuf.message import Message
import os
from pathlib import Path
import shutil
import zipfile
import shlex
import traceback
import signal
import json
import zstandard as zstd
import tarfile
import time

from libatlantis.protobuf import (
    DirectedFuzzerRequest,
    DirectedFuzzerResponse,
    DF_SUCCESS,
    DF_FAILURE,
)
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
)
from libmsa.kafka import Producer

from . import config

logger = logging.getLogger(__name__)

class DirectedFuzzingSession:
    def copy_to_task_dir(self, absolute_src: str, task_relative_dst: str, is_dir = False):
        task_relative_dst_path = self.task_dir_path.joinpath(task_relative_dst)
        if not is_dir:
            shutil.copy(absolute_src, task_relative_dst_path)
        else:
            shutil.copytree(absolute_src, task_relative_dst_path)
        return task_relative_dst_path

    def extract_tar_zst(self, src_path):
        dest_dir = self.task_dir_path.joinpath("seed_corpus")
        dest_dir.mkdir(parents=True, exist_ok=True)

        with open(src_path, 'rb') as compressed:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(compressed) as reader:
                with tarfile.open(fileobj=reader, mode='r|') as tar:
                    tar.extractall(path=dest_dir)

    def extract_input_corpus_zip(self, zip_path: str):
        zip_file = Path(zip_path)
        dest_dir = self.task_dir_path.joinpath("seed_corpus")

        if not zip_file.is_file():
            # we do not need to raise an error.
            # our run script will create the
            # seed corpus with empty seed by default
            return

        dest_dir.mkdir(parents=True, exist_ok=True)  # Create target dir if it doesn't exist

        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(dest_dir)

    def import_harness_build_config(self, artifacts_path: str, harness_id: str):
        build_config_file_path = f"{artifacts_path}/directed-fuzzing/{harness_id}-build-config.json"
        with open(build_config_file_path, "r") as build_config_file:
            self.build_config = json.load(build_config_file)

    def normalize_target_location(self, targetlocation: str) -> str:
        if ':' not in targetlocation:
            raise ValueError(f"Invalid format: '{targetlocation}' (expected 'file:line')")

        filepath, lineno = targetlocation.rsplit(':', 1)

        if not lineno.isdigit():
            raise ValueError(f"Invalid line number in: '{targetlocation}'")

        basename = os.path.basename(filepath)
        self.target_location = f"{basename}:{lineno}"

    def __init__(self, output_path: str, artifacts_path: str, cp_name: str,
                 harness_id: str, target_location: str, cores: list[int], session_id: str,
                 corpus_files: list[str], dictionary_files: list[str]):

        self.session_id = session_id

        self.task_dir_path = Path(f"{output_path}/directed-fuzzing-{self.session_id}")
        self.task_dir_path.mkdir(parents=True, exist_ok=True)

        # make sure the target location is in correct format
        self.normalize_target_location(target_location)

        # cp the bc file to taskdir
        bc_file = f"{harness_id}.bc"
        self.copy_to_task_dir(Path(f"{artifacts_path}/{harness_id}.bc").absolute(), bc_file)

        # import the build config
        self.import_harness_build_config(artifacts_path, harness_id)

        # prep the link flag
        libs_dir = self.copy_to_task_dir(Path(f"{artifacts_path}/directed-fuzzing/{harness_id}-shared-libs/").absolute(),
                              "shared-libs/", is_dir = True)
        link_flags_params = {"shared-lib-dir": libs_dir}

        # seed corpus
        self.extract_input_corpus_zip(Path(f"{artifacts_path}/{harness_id}_seed_corpus.zip").absolute())

        if corpus_files:
            logger.info(f'Found initial corpus files, using them in directed_fuzzing')
            corpus_files_paths = [Path(p) for p in corpus_files]
            for corpus_file_path in corpus_files_paths:
                self.extract_tar_zst(corpus_file_path)

        self.task_env = {
                "BULLSEYE_TASK_DIR": str(self.task_dir_path.absolute()),
                "BULLSEYE_TARGET_LOC": self.target_location,
                "BULLSEYE_BC_FILE": bc_file,
                "BULLSEYE_CONTEXT_MAX_DEPTH": str(config.BULLSEYE_CONTEXT_MAX_DEPTH),
                "BULLSEYE_LINKAGE_FLAGS": self.build_config["link_flags"].format(**link_flags_params),
                "BULLSEYE_BC_COMPILER": self.build_config["compiler"],
                "BULLSEYE_FUZZER_FLAGS": config.BULLSEYE_FUZZER_FLAGS,
                "BULLSEYE_SANITIZER": self.build_config["sanitizer"],
                "BULLSEYE_ARTIFACTS_DIR": artifacts_path,
        }

        if dictionary_files:
            logger.info(f'Found dictionary files, using them in directed_fuzzing')
            dictionary_files_paths = [Path(p) for p in dictionary_files]
            dict_args = ""
            for dict_file in dictionary_files_paths[:4]:
                dict_args += "-x " + str(dict_file.absolute()) + " "

            self.task_env["BULLSEYE_DICTIONARY_ARGS"] = dict_args

        core_mask = sum(1 << c for c in cores)
        core_mask_hex = hex(core_mask)

        self.compile_cmd = ['taskset', core_mask_hex, '/directed_fuzzing/compile-bc.sh']
        self.fuzz_cmd = ['taskset', core_mask_hex, '/directed_fuzzing/run.sh']
        self.compile_process = None
        self.fuzz_process = None
        self.compile_callback = None

    def get_env(self) -> dict[str, str]:
        # Merge with env set in docker
        env = os.environ.copy()
        env.update(self.task_env)
        return env

    def log_cmd(self, env, cmd):
        env_part = ' '.join(f'{k}={shlex.quote(v)}' for k, v in env.items())
        cmd_part = ' '.join(shlex.quote(arg) for arg in cmd)
        logger.info(f"Running: {env_part} {cmd_part}")

    def compile(self, response: DirectedFuzzerResponse, callback=None) -> None:
        response.fuzzer_session_id = self.session_id
        self.compile_callback = callback
        env = self.get_env()

        logger.info(f"Compiling harness for directed fuzzer Session: {self.session_id}")
        self.log_cmd(env, self.compile_cmd)

        outfile_path = self.task_dir_path.joinpath(config.COMPILE_OUT_LOG_FILE)
        errfile_path = self.task_dir_path.joinpath(config.COMPILE_ERR_LOG_FILE)
        
        with open(outfile_path, "w") as outfile, open(errfile_path, "w") as errfile:
            self.compile_process = subprocess.Popen(self.compile_cmd, env=env,
                                            stdout=outfile,
                                            stderr=errfile,
                                            preexec_fn=os.setsid)

            def wait_for_compile():
                success = True
                try:
                    exit_code = self.compile_process.wait(timeout=config.COMPILE_TIMEOUT)
                    if exit_code == 0:
                        response.status = DF_SUCCESS
                        response.aux = ""
                        success = True
                    elif exit_code == 1:
                        response.status = DF_FAILURE
                        response.aux = "Compilation error: configuration error"
                        success = False
                    elif exit_code == 2:
                        response.status = DF_FAILURE
                        response.aux = "Compilation error: no path to the target"
                        success = False
                    elif exit_code == 3:
                        response.status = DF_FAILURE
                        response.aux = "Compilation error: target location not found in codebase"
                        success = False
                    else:
                        response.status = DF_FAILURE
                        response.aux = "Compilation error: unknown error"
                        success = False
                except subprocess.TimeoutExpired:
                    self.kill_compiler()
                    response.status = DF_FAILURE
                    response.aux = "Compilation error: timeout"
                    success = False

                if self.compile_callback:
                    self.compile_callback(success, response)

            # Start the wait thread
            wait_thread = Thread(target=wait_for_compile)
            wait_thread.daemon = True
            wait_thread.start()

    def kill_compiler(self):
        if self.compile_process:
            if self.compile_process.poll() is None:
                os.killpg(self.compile_process.pid, signal.SIGTERM)

    def start_fuzzer(self, response: DirectedFuzzerResponse):
        env = self.get_env()

        logger.info(f"Starting Directed Fuzzer Session: {self.session_id}")
        self.log_cmd(env, self.fuzz_cmd)

        outfile_path = self.task_dir_path.joinpath(config.FUZZ_OUT_LOG_FILE)
        errfile_path = self.task_dir_path.joinpath(config.FUZZ_ERR_LOG_FILE)
        with open(outfile_path, "w") as outfile, open(errfile_path, "w") as errfile:
            self.fuzz_process = subprocess.Popen(self.fuzz_cmd, env = env,
                                            stdout = outfile,
                                            stderr = errfile,
                                            preexec_fn=os.setsid)

        corpus_path = self.task_dir_path.joinpath("bullseye-fuzz-out/default/queue")
        is_running = self.wait_for_path_to_exist(corpus_path)
        if not is_running:
            response.status = DF_FAILURE
            response.fuzzer_session_id = self.session_id
            # FIXME: update aux message for fuzzer corpus path not being found
            response.aux = "Fuzzer failed to start"
            # FIXME: should we kill the fuzzer here?
            self.kill_fuzzer()
        else:
            response.fuzzer_session_id = self.session_id
            response.status = DF_SUCCESS
            response.corpus_path = str(self.task_dir_path.joinpath("bullseye-fuzz-out/default/queue"))
            response.crashes_path = str(self.task_dir_path.joinpath("bullseye-fuzz-out/default/crashes"))

    def wait_for_path_to_exist(self, path: Path, timeout: int = 1200):
        start_time = time.time()
        while not path.exists():
            if time.time() - start_time > timeout:
                logger.error(f"Path {path} did not exist after {timeout} seconds")
                return False
            time.sleep(1)
        logger.info(f"Path {path} exists")
        return True

    def kill_fuzzer(self):
        if self.fuzz_process:
            if self.fuzz_process.poll() is None:
                os.killpg(self.fuzz_process.pid, signal.SIGTERM)

    def stop(self, response: DirectedFuzzerResponse):
        response.fuzzer_session_id = self.session_id
        logger.info(f"Stopping Directed Fuzzer Session: {self.session_id}")

        if not self.fuzz_process and not self.compile_process:
            response.status = DF_FAILURE
            response.aux = "[stop] No process is attached to this session"
            response.fuzzer_session_id = self.session_id
            return

        self.kill_compiler()
        self.kill_fuzzer()

        response.status = DF_SUCCESS

class DirectedFuzzerContext:
    def __init__(self):
        self.sessions: dict[str, DirectedFuzzingSession] = {}
        self.lock = Lock()
        self.response_producer = Producer(KAFKA_SERVER_ADDR, DIRECTED_FUZZER_RESPONSE_TOPIC)

    def send_response(self, response: DirectedFuzzerResponse):
        with self.lock:
            try:
                self.response_producer.send_message(response)
            except Exception as e:
                logger.error(f"Failed to send Kafka message: {e}")

    def insert_session(self, directed_fuzzing_session: DirectedFuzzingSession):
        with self.lock:
            self.sessions[directed_fuzzing_session.session_id] = directed_fuzzing_session

    def delete_session(self, directed_fuzzing_session: DirectedFuzzingSession):
        with self.lock:
            del self.sessions[directed_fuzzing_session.session_id]

    def get_session(self, session_id: str) -> Optional[DirectedFuzzingSession]:
        with self.lock:
            logger.info(f"sessions {self.sessions}") # TODO rm
            return self.sessions.get(session_id)

    def process_run_request(self, message: DirectedFuzzerRequest):
        response = DirectedFuzzerResponse()
        response.cmd = message.cmd
        response.fuzzer_session_id = message.fuzzer_session_id
        response.harness_id = message.harness_id
        response.node_idx = message.node_idx
        try:
            directedFuzzerSession = DirectedFuzzingSession(message.output_path,
                                                           message.artifacts_path,
                                                           message.cp_name,
                                                           message.harness_id,
                                                           message.location,
                                                           message.cores,
                                                           message.fuzzer_session_id,
                                                           message.corpus_files,
                                                           message.dictionary_files)

            # insert the session so that another thread can
            # interrupt and kill the fuzzing session compilation
            self.insert_session(directedFuzzerSession)

            def on_compile_complete(success: bool, compile_response: DirectedFuzzerResponse):
                if success:
                    # compilation succeeds, start the fuzzer
                    directedFuzzerSession.start_fuzzer(compile_response)
                # Send response via Kafka regardless of success/failure
                self.send_response(compile_response)

            directedFuzzerSession.compile(response, callback=on_compile_complete)

        except Exception as e:
            response.status = DF_FAILURE
            response.fuzzer_session_id = message.fuzzer_session_id
            tb_str = traceback.format_exc()
            response.aux = f"[run] Fuzzer failed to run: {e}\n{tb_str}"
            self.send_response(response)

    def process_stop_request(self, message: DirectedFuzzerRequest) -> DirectedFuzzerResponse:
        response = DirectedFuzzerResponse()
        response.cmd = message.cmd
        response.fuzzer_session_id = message.fuzzer_session_id
        response.harness_id = message.harness_id
        response.node_idx = message.node_idx
        try:
            directedFuzzerSession = self.get_session(message.fuzzer_session_id)
            if not directedFuzzerSession:
                response.status = DF_FAILURE
                response.aux = "[stop] Could not find fuzzer session"
                response.fuzzer_session_id = message.fuzzer_session_id
                return response

            directedFuzzerSession.stop(response)
            self.delete_session(directedFuzzerSession)

        except Exception as e:
            response.status = DF_FAILURE
            response.fuzzer_session_id = message.fuzzer_session_id
            tb_str = traceback.format_exc()
            response.aux = f"[stop] Failed to process stop request: {e}\n{tb_str}"

        return response

    def __del__(self):
        if hasattr(self, 'response_producer'):
            self.response_producer.close()
