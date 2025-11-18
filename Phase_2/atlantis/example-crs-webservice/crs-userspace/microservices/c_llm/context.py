from threading import Lock
import logging
from pathlib import Path
import threading
import glob
import time
import hashlib
import subprocess
import yaml
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    FUZZER_SEED_SUGGESTIONS_TOPIC,
)
from libatlantis.protobuf import SUCCESS
from libatlantis.protobuf import FuzzerSeeds
from libatlantis.protobuf import FuzzerBinaries
from libmsa.kafka.producer import Producer
from libCRS.util import run_cmd
from collections import defaultdict
from libatlantis.protobuf import (
    FuzzerLaunchAnnouncement, 
    FuzzerStopResponse,
)

from .mutator import invoke_llm_mutator
import os
import lldb
logger = logging.getLogger(__name__)
kafka_producer = Producer(KAFKA_SERVER_ADDR, FUZZER_SEED_SUGGESTIONS_TOPIC)
from libatlantis.constants import CRS_SCRATCH_DIR
from . import config
STORAGE_DIR = CRS_SCRATCH_DIR / "harness-builder-build"
class LLMMutatorContext:
    def __init__(self, interval: int = 60):
        self.lock = threading.Lock()
        self.interval = interval
        self.active_harnesses = set()
        self.corpus_folders = {}
        self.fuzz_target_path = {}
        self.source_folders = {}
        self.monitor_start = False
        self.cp_name = ""
        self.cp_src_path = ""
        self.node_idx = int(os.environ.get("NODE_IDX", 0))
        self.folder_last_corpus = {}
        self.timeout = 2 * 60 # The timeout set for the mutation
        self.name_mapping_lock= Lock()
        self.harness_to_cp = {}
        self.corpus_path_set = set()
        self.host_dir = Path("/c_llm_local")
        self.libafl_target = {}
        self.libfuzzer_target = {}
        self.oss_fuzz_target = {}
        self.harness_src = {}
        self.oss_fuzz_path = ""
    def register_launch_announcement(self, msg):
        with self.lock:
            harness_id = msg.harness_id
            self.cp_name = msg.cp_name
            self.cp_src_path = Path(msg.cp_src_path)
            self.oss_fuzz_path = Path(msg.oss_fuzz_path)
            logger.info(f"Register launch announcement for {harness_id}")
            corpus_dir_paths = msg.corpus_paths 
            source_dir_path = msg.cp_src_path
            fuzz_target_path = msg.binary_paths
            if harness_id not in self.active_harnesses:
                self.active_harnesses.add(harness_id)
            if harness_id not in self.corpus_folders:
                self.corpus_folders[harness_id] = set()
            for item in corpus_dir_paths:
                self.corpus_folders[harness_id].add(Path(item))
            if harness_id not in self.fuzz_target_path:
                self.fuzz_target_path[harness_id] = fuzz_target_path
                libafl_path = fuzz_target_path.libafl
                libfuzzer_path = fuzz_target_path.libfuzzer
                if not self.host_dir.exists():
                    self.host_dir.mkdir()
                libafl_local_path = Path(self.host_dir) / msg.nonce / "libafl/"
                libfuzzer_local_path = Path(self.host_dir) / msg.nonce / "libfuzzer/"
                oss_fuzz_local_path = Path(self.host_dir) / msg.nonce / "oss_fuzz"
                if not os.path.exists(libafl_local_path):
                    libafl_local_path.mkdir(parents=True, exist_ok=True)
                if not os.path.exists(libfuzzer_path):
                    libfuzzer_local_path.mkdir(parents=True, exist_ok=True)
                if not os.path.exists(oss_fuzz_local_path):
                    oss_fuzz_local_path.mkdir(parents=True, exist_ok=True)

                fs_copy(Path(libafl_local_path),Path(libafl_path).parent)
                fs_copy(Path(libfuzzer_local_path), Path(libfuzzer_path).parent)
                fs_copy(Path(oss_fuzz_local_path), Path(self.oss_fuzz_path/"build/out/" / self.cp_name))
                self.libafl_target[harness_id] = libafl_local_path / harness_id
                self.libfuzzer_target[harness_id] = libfuzzer_local_path / harness_id
                self.oss_fuzz_target[harness_id] = oss_fuzz_local_path / harness_id
            if harness_id not in self.source_folders:
                src_local_path = Path(self.host_dir) / msg.nonce / "src"
                if not os.path.exists(src_local_path):
                    src_local_path.mkdir(parents=True, exist_ok=True)
                fs_copy(Path(src_local_path), Path(source_dir_path))
                self.source_folders[harness_id] = src_local_path
            if harness_id not in self.harness_src:
                self.find_harness_source(msg.nonce)
    def __scan_corpus_dir(self, harness_id):
        if harness_id not in self.corpus_folders:
            return {}
        corpus_dirs = self.corpus_folders[harness_id]

        black_list = [".lafl_lock", ".tmp", ".metadata"]
        for corpus_dir in corpus_dirs:
            if not os.path.exists(corpus_dir):
                return {}
            logger.info(f"Polling corpus : {corpus_dir}")
            last_created_file = None
            last_created_time = 0
            if corpus_dir in self.folder_last_corpus:
                last_created_file, last_created_time = self.folder_last_corpus[corpus_dir]
            else:
                self.folder_last_corpus[corpus_dir] = (None, 0)
            try:
                for file_path in Path(corpus_dir).glob("*"):
                    try:
                        if any(str(file_path).endswith(b) for b in black_list):
                            continue
                        file_mtime = file_path.stat().st_mtime
                        if file_mtime > last_created_time:
                            last_created_time = file_mtime
                            last_created_file = file_path
                    except FileNotFoundError:
                        continue
                if last_created_file is not None:
                    self.folder_last_corpus[corpus_dir] = (last_created_file, last_created_time)
                    current_time = time.time()
                    if (current_time - last_created_time) > self.timeout:
                        logger.info(f"Last created file {last_created_file} has exceeded timeout {self.timeout} seconds")
                        logger.info(f"Let the llm to mutate the file")
                        if self.fuzz_target_path[harness_id]:
                            libafl_target_program = self.libafl_target[harness_id]
                            libfuzzer_target_program = self.libfuzzer_target[harness_id]
                            oss_fuzz_target_program = self.oss_fuzz_target[harness_id]
                            source_dir = self.source_folders[harness_id]
                            harness_src = self.harness_src[harness_id]

                            if libfuzzer_target_program is not None and source_dir is not None:
                                invoke_llm_mutator(harness_id, libfuzzer_target_program, last_created_file, source_dir, harness_src)
            except Exception as e:
                logger.error(f"Error scanning directory: {e}")
    def __monitor_corpus(self):
        while True:
            with self.lock:
                if self.active_harnesses:
                    logger.info(f"active_harnesses : {self.active_harnesses}")
                    for hid in self.active_harnesses:
                        logger.info(f"Polling corpus folders for {hid}")
                        self.__scan_corpus_dir(hid)
                        logger.info(f"** heartbeat ** -> monitoring corpus for harness {hid}")
                else:
                    logger.info("No active harnesses")
            time.sleep(self.interval)
    
    def start_monitoring(self):
        logger.info("Starting to monitor corpus folders")
        self.monitor_thread = threading.Thread(target=self.__monitor_corpus)
        self.monitor_thread.start()

    def deactivate_harness(self, harness_id: str):
        with self.lock:
            logger.info(f"Stopping monitoring {self.corpus_folders[harness_id]}")
            self.active_harnesses.remove(harness_id)
            self.corpus_folders.pop(harness_id)
    def find_harness_source(self, build_nonce):
        cp_proj_path = self.oss_fuzz_path / "projects" / self.cp_name
        config_path = cp_proj_path / ".aixcc/config.yaml"
        storage_path = Path(STORAGE_DIR)

        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)

            copied_src_path = storage_path / f"{build_nonce}_src"
            for harness in config['harness_files']:
                harness_id = harness['name']
                source_path = harness['path'].replace("$REPO", str(copied_src_path))
        
                if Path(source_path).exists():
                    self.harness_src[harness_id] = Path(source_path)
                else:
                    fallback_path = harness['path'].replace("$REPO", str(self.cp_src_path))
                    if Path(fallback_path).exists():
                        self.harness_src[harness_id] = Path(fallback_path)
                    else:
                        fallback_path = harness['path'].replace("$PROJECT", str(self.oss_fuzz_path)+"/projects/"+str(self.cp_name))
                        if Path(fallback_path).exists():
                            self.harness_src[harness_id] = Path(fallback_path)
                        else:
                            logger.info(f" Source file not found for harness {harness_id} at {source_path} or {fallback_path}")
        except Exception as e:
            logger.info(f"Exception: {e} (Line: {e.__traceback__.tb_lineno})")
def count_files(d : Path):
    if not d.exists():
        return 0
    if d.is_file():
        return 1
    total = 0
    for entry in d.iterdir():
        if entry.is_file():
            total += 1
        elif entry.is_dir():
            total += count_files(entry)
    return total
def fs_copy(dst: Path, src: Path) -> None:
    logger.info(f"synchronize the folder, src  : {src}, dst : {dst}")
    if not os.path.exists(dst):
        dst.mkdir(parents=True, exist_ok=True)

    if src.is_dir():
        src = f'{src}/.'
    
    subprocess.run(['rsync', '-a', str(src), str(dst)])