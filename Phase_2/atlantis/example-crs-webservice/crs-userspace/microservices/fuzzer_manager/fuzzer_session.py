import subprocess
import logging
import threading
import os
import configparser
import fcntl
import time
import re
from pathlib import Path
import json
from abc import ABC, abstractmethod
from enum import Enum
import signal
import select
import shlex
from dataclasses import dataclass
from typing import Callable
from datetime import datetime

from libatlantis.protobuf import (
    FuzzerRunResponse,
    SUCCESS, 
    FAILURE, 
    FUZZER_INIT,
    FUZZER_RUN,
)
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    LARGE_DATA_DIR,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_SEED_ADDITIONS_TOPIC,
    FUZZER_SEED_REQUESTS_TOPIC,
    FUZZER_SEED_UPDATES_TOPIC,
    NODE_CPU_CORES,
    IN_K8S,
    LARGE_DATA_DIR,
    NODE_NUM,
)
from libmsa.kafka import Producer

from . import config
from .utils import rsync, unzip, extract_tar_zst, flatten_directory, reap_children, run_and_log, filter_to_files

logger = logging.getLogger(__name__)

VERBOSE_FUZZER = os.environ.get("VERBOSE_FUZZER", "")

LIBFUZZER_MODES = {"libfuzzer", "ubsan", "msan", "sans"}

@dataclass
class FdHandler:
    buffer: bytes
    processor: Callable[[bytes], None]

@dataclass
class FuzzerStats:
    """Standardized fuzzer statistics"""
    harness_id: str
    exec_sec: float
    coverage: float
    crashes: int

class FuzzerSessionStatus(Enum):
    RUNNING = 0
    STOPPED = 1
    ERROR = 2
    ENDED = 3

class BaseFuzzerSession(ABC):
    """Base class for fuzzer-specific session implementations."""
    def __init__(
            self,
            cores: list[int],
            harness_id: str,
            session_id: str,
            work_dir_path: Path,
            fuzzer_env: dict[str, str], 
            time_left: int,
            nonce: str = None,
            initial_corpus_files: list[Path] = None,
            dictionary_files: list[Path] = None, 
            binary: Path = None,
            artifacts_dir: Path | None = None
    ):
        # Core session state
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.error_counter = 0
        self.error_threshold = 10
        self.init_delay_threshold = max(time_left - 60, 0) # timing is hard
        self.process = None
        self.panic_detect_thread = None
        self.log_thread = None
        self.verbose = os.environ.get("VERBOSE_FUZZER", "false").lower() in ["true", "1"]
        self.node_idx = int(os.environ.get("NODE_IDX", 0))
        self.session_id = session_id
        self.response_stage = FUZZER_INIT

        # Stats tracking
        self.last_info_dump = time.time()
        self.info_interval = 2  # interval for infodumps
        self.latest_stats = None # stores latest stats but can be set to None after flushing
        self.duplicate_stats = False # whether incoming stats are same as previous
        self.snapshot_stats = None # will always store the latest stats
        self.acceptable_speed = 1 # NOTE purely heuristic
        self.frozen_warning_threshold = 60 # flush logs and warn about inactivity
        self.frozen_error_threshold = 300 # flush logs and error about inactivity
        self.log_creation_timeout = self.init_delay_threshold # exit if log isn't created after timeout
        self.__fd_handlers = {}

        # Fuzzer configuration
        self.cores: list[int] = cores
        self.original_cores = self.cores
        self.harness_id: str = harness_id
        self.__init_work_dir_path(work_dir_path)
        self.initial_corpus_dir: Path = work_dir_path / "initial_corpus"
        self.output_dir: Path = work_dir_path / "crashes"
        # in honggfuzz, corpus and crashes are stored in the same directory
        self.base_env = fuzzer_env
        self.nonce = nonce
        self.initial_corpus_files: list[Path] = initial_corpus_files or []
        self.dictionary_files: list[Path] = dictionary_files or []
        self.binary: Path = binary
        self.artifacts_dir: Path | None = artifacts_dir

        self.producer = Producer(KAFKA_SERVER_ADDR, FUZZER_RUN_RESPONSE_TOPIC)

    def __init_work_dir_path(self, work_dir_path: Path):
        """
        Assigns our custom path and bind mounts it to /out in case of weird hardcoded runtime deps
        """
        self.work_dir_path = work_dir_path
        self.out_dir = work_dir_path
        work_dir_path.mkdir(parents=True, exist_ok=True)
        mounted_work_dir = Path('/out')
        # this could be dangerous race condition! caller (context.py) must lock
        if not mounted_work_dir.is_dir() or not any(mounted_work_dir.iterdir()):
            mounted_work_dir.mkdir(parents=True, exist_ok=True)
            run_and_log(['mount', '--bind', str(work_dir_path), str(mounted_work_dir)])
            self.out_dir = mounted_work_dir
        
    def info(self, msg):
        logger.info(f'(FuzzerSession with mode={self.mode}) {msg}')

    def warning(self, msg):
        logger.warning(f'(FuzzerSession with mode={self.mode}) {msg}')

    def error(self, msg):
        logger.error(f'(FuzzerSession with mode={self.mode}) {msg}')

    def __update_status(self):
        if self.process is None:
            logger.info(f"Fuzzer {self.harness_id} has no handle")
            self._status = FuzzerSessionStatus.ERROR
        elif self.process.poll() is None:
            logger.info(f"Fuzzer {self.harness_id} is running")
            self._status = FuzzerSessionStatus.RUNNING
        else:
            logger.info(f"Fuzzer {self.harness_id} ended with return code {self.process.returncode}")
            self._status = FuzzerSessionStatus.ENDED

    @property
    def status(self) -> FuzzerSessionStatus:
        self.__update_status()
        return self._status

    @property
    @abstractmethod
    def mode(self) -> str:
        """The mode of this fuzzer session. Should be implemented by subclasses."""
        pass

    @property
    @abstractmethod
    def crashes_paths(self) -> list[str]:
        pass

    @property
    @abstractmethod
    def corpus_paths(self) -> list[str]:
        pass

    def prepare_command(self) -> str:
        """Prepare the command to run the fuzzer. Should be implemented by subclasses."""
        return f"/fuzzer_manager/run_fuzzer {self.binary.name}"

    def check_fuzzer_successful(self) -> bool:
        """Check if fuzzer has started successfully by looking for stats output"""
        sleep_interval = 0.5
        threshold = int(self.init_delay_threshold // sleep_interval)
        check = 0
        while True:
            time.sleep(sleep_interval)
            if not self.snapshot_stats:
                check += 1
            else:
                break
            if check > threshold:
                self.response_stage = FUZZER_RUN # this doesn't seem right but whatever, not used by __init__.py
                return False
        self.response_stage = FUZZER_RUN
        return True

    def run(self):
        self.setup()
        cmd = self.prepare_command()
        self.info(f'Running fuzzer with cmd: {cmd}')
        self.start(cmd)

        if self.process is None:
            self.error('Fuzzer process not started')
            self.kill()

        self.setup_monitoring()

        for handler in logging.getLogger().handlers:
            handler.flush()
            
    def setup_monitoring(self):
        """Set up monitoring threads for the fuzzer"""
        self.panic_detect_thread = threading.Thread(target=self._monitor_std_streams, daemon=True)
        self.panic_detect_thread.start()
        
        if self.needs_logging_thread:
            self.log_thread = threading.Thread(target=self._monitor_log_file, daemon=True)
            self.log_thread.start()
        else:
            self.log_thread = None

    @property
    @abstractmethod
    def needs_logging_thread(self) -> bool:
        """Whether this fuzzer type needs a separate logging thread.
        Must be implemented by subclasses to explicitly declare logging needs."""
        pass

    def setup(self):
        if not IN_K8S:
            self.cores = [core + NODE_CPU_CORES * self.node_idx for core in self.cores]

        # with the delete flag, we make the work_dir a copy of the build's out directory
        if self.binary:
            rsync(self.binary.parent, self.work_dir_path, delete=True)

        # setup initial corpus and dicts
        self.initial_corpus_dir.mkdir(parents=True, exist_ok=True)
        # LARGE_DATA_DIR / f"seeds_collector/initial_corpus/{unique_id}:{timestamp}.tar.zst"
        seeds_collector_initial_corpus_dir = LARGE_DATA_DIR / "seeds_collector" / "initial_corpus"
        seeds_collector_initial_corpus_used = False
        latest_corpus_file_paths = []
        if seeds_collector_initial_corpus_dir.exists():
            for node_idx in range(NODE_NUM):
                latest_corpus_file_path = None
                latest_dt = datetime.strptime("20200101_000000", "%Y%m%d_%H%M%S")
                pattern = f"{self.harness_id}:{node_idx}:*.tar.zst"
                for corpus_file_path in seeds_collector_initial_corpus_dir.glob(pattern):
                    timestamp = corpus_file_path.name.split('.')[0].split(':')[-1] # cannot use stem because .tar.zst
                    try:
                        dt = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                    except ValueError:
                        logger.error(f"Invalid timestamp format: {timestamp}")
                        continue
                    if dt > latest_dt:
                        latest_dt = dt
                        latest_corpus_file_path = corpus_file_path
                if latest_corpus_file_path:
                    latest_corpus_file_paths.append(latest_corpus_file_path)

            for corpus_file_path in latest_corpus_file_paths:
                self.info(f'Found initial corpus files from seeds collector, unpacking to {self.initial_corpus_dir}...')
                extract_tar_zst(corpus_file_path, self.initial_corpus_dir)
                seeds_collector_initial_corpus_used = True

        if not seeds_collector_initial_corpus_used:
            logger.info("No initial corpus files from seeds collector found, try to use initial corpus files from osv-analyzer")
            if self.initial_corpus_files:
                self.info(f'Found initial corpus files, unpacking to {self.initial_corpus_dir}...')
                for corpus_file_path in self.initial_corpus_files:
                # shutil.unpack_archive(corpus_file_path, self.initial_corpus_dir)
                    extract_tar_zst(corpus_file_path, self.initial_corpus_dir)
            else:
                self.info('No initial corpus files found, creating dummy file...')
                (self.initial_corpus_dir / 'dummy.txt').write_bytes(b'A' * 3)

        # also copy the seeds we shared into the initial corpus
        # NOTE: there is a very slight chance of name collision
        SEED_SHARE_DIR = os.environ.get("SEED_SHARE_DIR")
        if SEED_SHARE_DIR:
            shared_seeds_dir = Path(SEED_SHARE_DIR) / "crs-userspace" / self.harness_id
            if shared_seeds_dir.exists():
                self.info('Found shared seeds, copying into initial corpus...')
                rsync(shared_seeds_dir, self.initial_corpus_dir)
        
        # the seed corpus from oss-fuzz is unpacked in run_fuzzer

        flatten_directory(self.initial_corpus_dir) 
        filter_to_files(self.initial_corpus_dir)

        if self.dictionary_files:
            self.info('Found dictionary files, copying into work_dir...')
            for dictionary_file_path in self.dictionary_files:
                rsync(dictionary_file_path, self.work_dir_path)

        if self.mode in LIBFUZZER_MODES:
            engine = "libfuzzer"
        else:
            engine = self.mode
                
        fuzzer_env = {
            "OUT": str(self.out_dir),
            "FUZZING_ENGINE": engine,
            "SANITIZER": "address",
            "RUN_FUZZER_MODE": "noninteractive",
            "FUZZER_OUT": str(self.output_dir),
            "CORPUS_DIR": str(self.initial_corpus_dir), # for libfuzzer
            "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
            "TSAN_OPTIONS": "abort_on_error=1",
            "UBSAN_OPTIONS": "abort_on_error=1",
            "MSAN_OPTIONS": "abort_on_error=1",
            "LSAN_OPTIONS": "abort_on_error=1:symbolize=0", # symbolize=0 was from afl
            "CORES": ",".join([str(core) for core in self.cores]),
        }

        self.fuzzer_env = self.base_env.copy()
        self.fuzzer_env.update(fuzzer_env)

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def start(self, cmd: str):
        stderr = subprocess.PIPE
        stdout = subprocess.PIPE
        self.process = subprocess.Popen(cmd, shell=True, env=self.fuzzer_env, preexec_fn=os.setsid, stdout=stdout, stderr=stderr, cwd=self.out_dir)

    def stop(self):
        self.stop_event.set()
        if self.panic_detect_thread:
            logging.info("Waiting for std stream monitoring thread")
            self.panic_detect_thread.join()
            self.panic_detect_thread = None
        if hasattr(self, 'log_thread') and self.log_thread:
            logging.info("Waiting for log file monitoring thread")
            self.log_thread.join()
            self.log_thread = None
        if self.process:
            try:
                logging.info("Sending SIGTERM to fuzzing process")
                os.killpg(self.process.pid, signal.SIGTERM)
                self.process.wait(timeout=60)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                self.kill()
            finally:
                reap_children(self.process.pid)

    def kill(self):
        if self.process and self.process.poll() is None:
            self.stop_event.set()
            if self.panic_detect_thread:
                logging.info("Waiting for std stream monitoring thread from kill()")
                self.panic_detect_thread.join()
                self.panic_detect_thread = None
            if hasattr(self, 'log_thread') and self.log_thread:
                logging.info("Waiting for log file monitoring thread from kill()")
                self.log_thread.join()
                self.log_thread = None
            try:
                logging.info("Sending SIGKILL to fuzzing process")
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait()
            except ProcessLookupError:
                pass
            reap_children(self.process.pid)

    @abstractmethod
    def _monitor_log_file(self):
        """Monitor and parse the fuzzer's external log file. Override in subclass."""
        pass

    def _should_dump_info(self) -> bool:
        """Check if enough time has passed since last info dump"""
        current_time = time.time()
        delta = current_time - self.last_info_dump

        ret = (
            (not self.duplicate_stats)
            and delta >= self.info_interval
            and self.latest_stats
        )

        errmsg = f"no update to fuzzer log in {delta} seconds"
        
        if delta >= self.frozen_warning_threshold and int(delta) % 10 == 0 and delta - int(delta) <= 0.11:
            # force log flush even if duplicate. handles if exec is still too slow
            self.warning(errmsg)
            if self.snapshot_stats:
                self.latest_stats = self.snapshot_stats
                return True
        return ret

    def _update_info_dump_time(self):
        """Update the last info dump timestamp"""
        self.last_info_dump = time.time()

    def _dump_stats_if_needed(self, stats: FuzzerStats):
        """Store stats and dump if interval has passed"""
        self.duplicate_stats = stats == self.snapshot_stats
        self.latest_stats = stats
        self.snapshot_stats = stats
        if self._should_dump_info():
            self._dump_stats()
            self._update_info_dump_time()

    def _dump_stats(self):
        """Dump the latest stats"""
        if not self.latest_stats:
            return
        stats = self.latest_stats
        if stats.exec_sec < self.acceptable_speed and self.mode not in LIBFUZZER_MODES:
            self._handle_fuzzer_error(f"Fuzzer {self.harness_id} is running too slow, exec_sec={stats.exec_sec}")
        self.info(f"harness={stats.harness_id} exec_sec={stats.exec_sec} coverage={stats.coverage} crashes={stats.crashes}")
        self.latest_stats = None

    def __make_line_processor(self, log_method, handler):
        """Factory function to create line processors"""
        def process_line(line_bytes):
            try:
                output = line_bytes.decode("utf-8")
                if self.verbose and output.strip():
                    log_method(output.rstrip('\n'))
                handler(output)
            except UnicodeDecodeError:
                pass
        return process_line

    def __handle_fd_data(self, fd):
        """Generic handler for file descriptor data"""
        handler = self.__fd_handlers[fd]
        try:
            # Read available data (non-blocking)
            chunk = os.read(fd, 4096)
            if not chunk:  # EOF
                # Process any remaining buffered data as final line
                if handler.buffer:
                    handler.processor(handler.buffer)
                    handler.buffer = b""
                return
            
            # Add to buffer
            handler.buffer += chunk
            
            # Process complete lines
            while b'\n' in handler.buffer:
                line, handler.buffer = handler.buffer.split(b'\n', 1)
                handler.processor(line + b'\n')
                
        except (OSError, BlockingIOError):
            # No data available (shouldn't happen after select, but be safe)
            pass

    def __setup_fd_handlers(self):
        stderr_fd = self.process.stderr.fileno()
        stdout_fd = self.process.stdout.fileno()
        fcntl.fcntl(stderr_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(stdout_fd, fcntl.F_SETFL, os.O_NONBLOCK)
        self.__fd_handlers = {
            stderr_fd: FdHandler(
                buffer=b"",
                processor=self.__make_line_processor(self.error, self._handle_error_output),
            ),
            stdout_fd: FdHandler(
                buffer=b"",
                processor=self.__make_line_processor(self.info, self._handle_stdout_output),
            ),
        }
        
    def _monitor_std_streams(self):
        """Monitor and handle stdout and stderr streams from the fuzzer process"""
        self.__setup_fd_handlers()
        
        while not self.stop_event.is_set():
            try:
                ready, _, _ = select.select(list(self.__fd_handlers.keys()), [], [], 0.1)
                if not ready:
                    # Check if we need to dump stats even without new output
                    if self._should_dump_info() and self.latest_stats:
                        self._dump_stats()
                        self._update_info_dump_time()
                    continue

                for fd in ready:
                    self.__handle_fd_data(fd)
            except OSError:
                self.__setup_fd_handlers()

    @abstractmethod
    def _handle_error_output(self, error_output: str):
        """Handle fuzzer-specific error output. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def _handle_stdout_output(self, output: str):
        """Handle fuzzer-specific stdout output. Must be implemented by subclasses."""
        pass


    def __create_template_fuzzer_response(self):
        response = FuzzerRunResponse()
        response.fuzzer_session_id = self.session_id
        response.harness_id = self.harness_id
        response.node_idx = self.node_idx
        response.cores.extend(self.original_cores)
        response.mode = self.mode
        response.time_left = self.init_delay_threshold # only case where this is used is FAILURE + FUZZER_INIT is init timeout
        return response
    
    def send_mock_init_message(self):
        response = self.__create_template_fuzzer_response()
        response.status = SUCCESS
        response.aux = f"Fuzzer is running in {self.mode} mode"
        response.stage = FUZZER_INIT
        self.producer.send_message(response)
    
    # WARNING: this ends the whole container!!!!!!!!
    def send_runtime_failure_message(self, message: str):
        response = self.__create_template_fuzzer_response()
        response.status = FAILURE
        response.aux = message
        response.stage = self.response_stage
        response.time_left = self.init_delay_threshold # only case where FUZZER_INIT is init timeout, so use this
        self.producer.send_message(response)
        # hacky way of killing tini itself
        logger.info("Fuzzer will now commit suicide")
        for handler in logging.getLogger().handlers:
            handler.flush()
        os._exit(0)
        #subprocess.run(["kill", "-SIGTERM", "1"])

    def _handle_fuzzer_error(self, error_msg: str):
        """Common error handling logic for fuzzer errors"""
        with self.lock:
            # any panic detection should be considered as runtime error
            self.error_counter += 1
            if self.error_counter > self.error_threshold:
                # need to satisfy controller first!
                if self.response_stage == FUZZER_INIT:
                    self.send_mock_init_message()

                self.response_stage = FUZZER_RUN
                self.error(f"Fuzzer {self.harness_id} has {self.error_counter} errors, sending failure message")
                self.send_runtime_failure_message(error_msg)
        self.error(error_msg)


class LibAFLFuzzerSession(BaseFuzzerSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.error_threshold = 10
        self.corpus_dir: Path = self.work_dir_path / "corpus"
        self.fuzzer_config_path: Path = self.work_dir_path / f"fuzzer_config_{self.harness_id}.json"
        self.fuzzer_config = None
        self.fuzzer_log_path: Path = self.work_dir_path / "fuzzer.log"
        self.traceback_collection = False
        self.traceback_lines = 0
        self.traceback_limit = 100

    @property
    def mode(self) -> str:
        return "libafl"

    @property
    def needs_logging_thread(self) -> bool:
        """LibAFL needs a separate logging thread since it doesn't use stdout for stats"""
        return True

    @property
    def crashes_paths(self) -> list[str]:
        return [str(self.output_dir)]

    @property
    def corpus_paths(self) -> list[str]:
        return [str(self.corpus_dir)]

    def check_setup(self):
        if not self.fuzzer_config_path.exists():
            self.info('Fuzzer config path does not exist, fuzzer not setup correctly')
            return False
        return True
    
    # def prepare_command(self) -> str:
    #     return f"/out/{self.binary.name}"

    def get_fuzzer_config(self):
        """
        fuzzer_config = {
            "broker_port" : config.BROKER_PORT,
            "centralized_broker_port" : config.CENTRALIZED_BROKER_PORT,
            "campaign_id" : harness_id,
            "harness_id" : harness_id,
            "initial_corpus_dir" : str(initial_corpus_dir),
            "output_dir" : str(output_dir),
            "kafka_broker_addr" : kafka_hostname,
            "kafka_seed_additions_topic" : FUZZER_SEED_ADDITIONS_TOPIC,
            "kafka_seed_requests_topic": FUZZER_SEED_REQUESTS_TOPIC,
            "kafka_seed_updates_topic": FUZZER_SEED_UPDATES_TOPIC,
            "corpus_dir" : str(corpus_dir),
            "log_file" : str(log_file_path),
            "cores" : cores,
            "dictionary_files": [str(p) for p in dictionary_files],
        }
        """
        with self.fuzzer_config_path.open('r') as f:
            self.fuzzer_config = json.load(f)
            self.info(f'Fuzzer config: {self.fuzzer_config}')
    
    def setup_fuzzer_config(self):
        """Set up the fuzzer configuration and environment"""
        # use the mounted_work_dir since the actual fuzzer will use this

        fuzzer_config = {
            "broker_port": config.BROKER_PORT,
            "centralized_broker_port": config.CENTRALIZED_BROKER_PORT,
            "campaign_id": self.harness_id,
            "harness_id": self.harness_id,
            "initial_corpus_dir": str(self.initial_corpus_dir),
            "output_dir": str(self.output_dir),
            "kafka_broker_addr": KAFKA_SERVER_ADDR.split(':')[0],
            "kafka_seed_additions_topic": FUZZER_SEED_ADDITIONS_TOPIC,
            "kafka_seed_requests_topic": FUZZER_SEED_REQUESTS_TOPIC,
            "kafka_seed_updates_topic": FUZZER_SEED_UPDATES_TOPIC,
            "corpus_dir": str(self.corpus_dir),
            "log_file": str(self.fuzzer_log_path),
            "cores": self.cores,
            "dictionary_files": [str(p) for p in self.dictionary_files],
        }

        # dot-options parsing
        options_file = self.work_dir_path / f'{self.harness_id}.options'
        if options_file.is_file():
            parser = configparser.ConfigParser()
            parser.read(options_file)
            
            libfuzzer_section = "libfuzzer"
            if parser.has_section(libfuzzer_section):
                options = parser[libfuzzer_section]
                if "dict" in options:
                    dict_path = self.work_dir_path / options["dict"]
                    fuzzer_config["dictionary_files"].append(str(dict_path))
                if "max_len" in options:
                    fuzzer_config["max_len"] = int(options["max_len"])
                if "timeout" in options:
                    fuzzer_config["timeout"] = int(options["timeout"])
        
        # setup work_dir
        with self.fuzzer_config_path.open("w", encoding="utf-8") as f:
            json.dump(fuzzer_config, f)

        self.fuzzer_config = fuzzer_config

    def setup(self):
        super().setup()

        fuzzer_env = {
            "LD_LIBRARY_PATH": str(self.artifacts_dir) if self.artifacts_dir else "",
            "FUZZER_CONFIG_PATH": str(self.fuzzer_config_path),
            "FUZZER_LOG_FILE": str(self.fuzzer_log_path),
            "RUST_BACKTRACE": "full",
        }
        if self.verbose:
            fuzzer_env["RUST_LOG"] = "info"
        
        self.fuzzer_env.update(fuzzer_env)
        
        # used to poll in old code, probably for multi harness or sth
        self.setup_fuzzer_config()
        # self.info('Waiting for fuzzer to be setup...')
        # while not self.check_setup():
        #     time.sleep(0.1)

    def _handle_error_output(self, error_output: str):
        """Handle LibAFL-specific error output including panic traceback collection"""
        if "thread '<unnamed>' panicked" in error_output:
            self.traceback_collection = True
            self._handle_fuzzer_error("***libafl runtime error, please fallback to libafl***, this is actual runtime error")
        
        if self.traceback_collection:
            self.error(error_output)
            self.traceback_lines += 1
            
            if self.traceback_lines >= self.traceback_limit:
                self.error("Thread panic detected, killing process")
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except Exception as e:
                    self.error(f"Error killing process: {e}")
                finally:
                    os.killpg(self.process.pid, signal.SIGKILL)
                if not self.stop_event.is_set():
                    # restart fuzzer
                    self.info("Restarting fuzzer...")
                    self.start(self.prepare_command())
                self.traceback_lines = 0
                self.traceback_collection = False

    def _handle_stdout_output(self, output: str):
        """Handle LibAFL stdout - no special handling needed"""
        pass

    def second_last_line(self):
        result = subprocess.run(f'tail -n2 "{self.fuzzer_log_path}" | head -n1',
                shell=True,
                capture_output=True,
                text=True
            )
        return result.stdout.strip()

    def _monitor_log_file(self):
        """Monitor LibAFL log file"""
        # First check if log file exists
        check = 0
        sleep_interval = 0.5
        while not self.stop_event.is_set():
            if not self.fuzzer_log_path.exists():
                check += 1
                if check > int(self.log_creation_timeout // sleep_interval):
                    self.send_runtime_failure_message(f"LibAFL log file not created after {self.log_creation_timeout} seconds")
                    return
                time.sleep(sleep_interval)
                continue
            break

        # Now monitor the log file
        while not self.stop_event.is_set():
            try:
                # might not exist yet
                tail = self.second_last_line()
                if tail:
                    raw_stats = json.loads(tail)
                    exec_sec = raw_stats["exec_sec"]
                    num = 0
                    denom = 0
                    for c in raw_stats["client_stats"]:
                        if c["enabled"]:
                            ratio = c["user_monitor"]["edges"]["value"]["Ratio"]
                            num += ratio[0]
                            denom += ratio[1]
                    coverage = num / denom if denom > 0 else 0
                    blist = {".lafl_lock", ".tmp", ".metadata"}
                    crashes = sum(1 for entry in self.output_dir.iterdir()
                                  if entry.is_file() and entry.suffix not in blist)
                    
                    stats = FuzzerStats(
                        harness_id=self.harness_id,
                        exec_sec=exec_sec,
                        coverage=coverage,
                        crashes=crashes
                    )
                    self._dump_stats_if_needed(stats)
            except Exception as e:
                self._handle_fuzzer_error(f"Error logging fuzzer: {e}")
            self.stop_event.wait(self.info_interval) # wakes up when stop_event is set

class LibFuzzerSession(BaseFuzzerSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pattern = re.compile(
            r"#\d+: cov: (?P<cov>\d+) .*? exec/s: (?P<execs>\d+) .*?oom/timeout/crash: \d+/\d+/(?P<crash>\d+)"
        )

    @property
    def mode(self) -> str:
        return "libfuzzer"

    @property
    def needs_logging_thread(self) -> bool:
        """LibFuzzer doesn't need a separate logging thread since it uses stdout"""
        return False

    @property
    def crashes_paths(self) -> list[str]:
        return [str(self.output_dir)]

    @property
    def corpus_paths(self) -> list[str]:
        return [str(self.initial_corpus_dir)]
    
    def prepare_command(self) -> str:
        """
            SHELL = "#!/bin/bash\n"
            SHELL += "cd /out\n"
            SHELL += f"./{binary_name} -artifact_prefix=/out/{crash_dir_name}/ "
            SHELL += f"-fork_corpus_groups=1 -ignore_crashes=1 "
            SHELL += f"-use_value_profile=1 "
            SHELL += f"-fork={len(cpu_list)} ./{corpus_dir_name}\n"
        """

        output_dir = str(self.output_dir)
        if not output_dir.endswith('/'):
            output_dir += '/'
        
        cmd = super().prepare_command()
        cmd += f" -artifact_prefix={output_dir}"
        cmd += " -fork_corpus_groups=1 -ignore_crashes=1 -use_value_profile=1"
        cmd += f" -fork={len(self.cores)}"
        # NOTE initial_corpus_dir is passed in via $CORPUS_DIR in run_fuzzer
        return cmd

    def _handle_error_output(self, error_output: str):
        """Handle LibFuzzer-specific error patterns"""
        match = self.pattern.search(error_output)
        if match:
            stats = FuzzerStats(
                harness_id=self.harness_id,
                exec_sec=float(match.group("execs")),
                coverage=float(match.group("cov")),
                crashes=int(match.group("crash"))
            )
            self._dump_stats_if_needed(stats)
        if "ERROR: libFuzzer" in error_output or "FATAL:" in error_output:
            self.error(error_output)
            # self._handle_fuzzer_error("LibFuzzer encountered fatal error")

    def _handle_stdout_output(self, output: str):
        """Handle LibFuzzer stdout - no special handling needed"""
        pass

    def _monitor_log_file(self):
        """Run logging for LibFuzzer"""
        pass

class AFLFuzzerSession(BaseFuzzerSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pattern = re.compile(r"(\d+)\scrashes saved.*?exec_us=(\d+).*?map=(\d+)")
        self.__set_fuzzer_log()

    def __set_fuzzer_log(self):
        self.fuzzer_log_path = self.output_dir / f"fuzzer-{self.cores[0]}/fuzzer_stats"
        
    @property
    def mode(self) -> str:
        return "afl"

    @property
    def needs_logging_thread(self) -> bool:
        return True

    def setup(self):
        super().setup()

        # NOTE turns out that zmqmutator gets glob copied into /out along with other afl stuff
        zmqmutator_path = self.work_dir_path / 'libzmqmutator.so'

        fuzzer_env = {
            "FUZZER": self.harness_id,
            "AFL_CUSTOM_MUTATOR_LIBRARY": str(zmqmutator_path),
        }
        self.fuzzer_env.update(fuzzer_env)

        self.__set_fuzzer_log() # update log because cores may be changed

    @property
    def crashes_paths(self) -> list[str]:
        return [
            str(self.output_dir / f"fuzzer-{core}/crashes")
            for core in self.cores
        ]

    @property
    def corpus_paths(self) -> list[str]:
        return [
            str(self.output_dir / f"fuzzer-{core}/queue")
            for core in self.cores
        ]

    def __extract_stats(self, stat_configs: dict[str, type]):
        """
        Extract multiple stats from AFL fuzzer stats text in a single pass.

        Args:
            stats_text (str): The AFL fuzzer stats as a string
            stat_configs (dict): Dictionary mapping stat names to their expected types
                                e.g., {'execs_per_sec': float, 'edges_found': int}

        Returns:
            dict: Dictionary with stat names as keys and extracted values
        """
        stats_text = self.fuzzer_log_path.read_text()
        results = {stat_name: None for stat_name in stat_configs.keys()}

        for line in stats_text.strip().split('\n'):
            # Check if this line contains any of our target stats
            for stat_name, value_type in stat_configs.items():
                if line.startswith(stat_name) and results[stat_name] is None:
                    # Split on ':' and get the value part
                    parts = line.split(':', 1)
                    if len(parts) == 2:
                        try:
                            results[stat_name] = value_type(parts[1].strip())
                        except ValueError:
                            results[stat_name] = None
                    break  # Found a match, move to next line

            # Early exit if all stats found
            if all(value is not None for value in results.values()):
                break

        return results
    
    def _handle_error_output(self, error_output: str):
        """Handle AFL-specific error patterns"""
        if "PROGRAM ABORT" in error_output:
            self.error(error_output)
            self._handle_fuzzer_error("***afl runtime error, please fallback to libfuzzer***")

    def _handle_stdout_output(self, output: str):
        """Handle AFL stdout including performance metrics"""
        pass

    def _monitor_log_file(self):
        """Run logging for AFL"""
        check = 0
        sleep_interval = 0.5
        while not self.stop_event.is_set():
            if not self.fuzzer_log_path.exists():
                check += 1
                if check > int(self.log_creation_timeout // sleep_interval):
                    self.send_runtime_failure_message(f"AFL log file not created after {self.log_creation_timeout} seconds")
                    return
                time.sleep(sleep_interval)
                continue
            break

        # Now monitor the log file
        while not self.stop_event.is_set():
            try:
                stats_dict = self.__extract_stats({
                    'execs_per_sec': float,
                    'edges_found': int,
                    'total_edges': int,
                    'saved_crashes': int,
                    'corpus_count': int,
                })
                exec_sec = stats_dict['execs_per_sec']
                coverage = stats_dict['edges_found'] / stats_dict['total_edges'] if stats_dict['total_edges'] > 0 else 0.0
                crashes = stats_dict['saved_crashes']
                stats = FuzzerStats(
                    harness_id=self.harness_id,
                    exec_sec=exec_sec,
                    coverage=coverage,
                    crashes=crashes
                )
                self._dump_stats_if_needed(stats)
            except Exception as e:
                self._handle_fuzzer_error(f"Error logging fuzzer: {e}")
            self.stop_event.wait(self.info_interval) # wakes up when stop_event is set

class UBSanFuzzerSession(LibFuzzerSession):
    @property
    def mode(self) -> str:
        return "ubsan"

class MSanFuzzerSession(LibFuzzerSession):
    @property
    def mode(self) -> str:
        return "msan"

class SansFuzzerSession(LibFuzzerSession):
    @property
    def mode(self) -> str:
        return "sans"

