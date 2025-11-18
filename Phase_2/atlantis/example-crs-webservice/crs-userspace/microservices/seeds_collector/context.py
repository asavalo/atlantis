from dataclasses import dataclass
import logging
import os
import subprocess
from pathlib import Path
import threading
import glob
import time
import hashlib
from datetime import datetime
import tarfile
import zstandard as zstd
from watchdog.events import FileSystemEventHandler, FileClosedEvent
from watchdog.observers import Observer

from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    FUZZER_SEED_SUGGESTIONS_TOPIC,
    LARGE_DATA_DIR,
)
from libatlantis.protobuf import SUCCESS
from libatlantis.protobuf import FuzzerSeeds
from libmsa.kafka.producer import Producer
from libCRS.util import run_cmd
from libatlantis.constants import CRS_SCRATCH_DIR, SHARED_CRS_DIR

from . import config

logger = logging.getLogger(__name__)
kafka_producer = Producer(KAFKA_SERVER_ADDR, FUZZER_SEED_SUGGESTIONS_TOPIC)

GENERAL_ORIGIN = "general_fuzzing"
DIRECTED_ORIGIN = "directed_fuzzing"
CUSTOM_ORIGIN = "custom_fuzzing"

BATCH_SIZE = 500000 # 0.5MB


def get_unique_id(harness_id: str, origin: str) -> str:
    return f"{origin}:{harness_id}"

def get_origin(unique_id: str) -> str:
    if ":" not in unique_id:
        return "seeds_collector"
    return unique_id.split(":")[0]

def b2b_checksum(path, chunk_size=1048576):  # 1MB chunks
    hasher = hashlib.blake2b()
    with open(path, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def send_seed_suggestions(harness_id: str, file_paths: list[Path]):
    """
    Send seed suggestions to the seed suggestions topic.
    """
    global kafka_producer

    byte_len = 0
    data_batch = []
    for fp in file_paths:
        try:
            data_batch.append(fp.read_bytes())
            byte_len += len(fp.read_bytes())
            if byte_len >= BATCH_SIZE:
                data = FuzzerSeeds()
                data.harness_id = harness_id
                data.origin = "seeds_collector"
                data.data.extend(data_batch)
                logger.info(f"Sending {len(data.data)} seeds to ensembler")
                for handler in logging.getLogger().handlers:
                    handler.flush()
                kafka_producer.send_message(data)
                data_batch = []
                byte_len = 0
        except FileNotFoundError:
            pass

    # send last batch if any
    if data_batch:
        data = FuzzerSeeds()
        data.harness_id = harness_id
        data.origin = "seeds_collector"
        data.data.extend(data_batch)
        logger.info(f"Sending {len(data.data)} seeds to ensembler")
        for handler in logging.getLogger().handlers:
            handler.flush()
        kafka_producer.send_message(data)

def saving_seeds(from_dir: Path, to_dir: Path):
    """
    Save the seeds from the from_dir to the to_dir, excluding files ending with 'lafl_lock', 'tmp', 'metadata'.
    """
    logger.info(f"Saving seeds from {from_dir} to {to_dir}")
    run_cmd(["rsync", "-a", "--exclude", "*.lafl_lock", "--exclude", "*.tmp", "--exclude", "*.metadata", "--exclude", "*-[0-9]*", str(from_dir)+"/", to_dir])

def compress_and_save_seeds(from_dir: Path, to_dir: Path, harness_id: str):
    """
    1. Find old tarballs in the to_dir with the same node_idx and harness_id and delete them
    2. Gets a new compressed file name
    3. Compress the seeds in the from_dir and save them to the to_dir
    4. During this function call, from_dir should be locked
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    compressed_file_prefix = f"{harness_id}:{config.NODE_IDX}"
    pattern = f"{compressed_file_prefix}:*.tar.zst"
    for f in to_dir.glob(pattern):
        f.unlink()

    compressed_file_name = f"{compressed_file_prefix}:{timestamp}.tar.zst"
    logger.info(f"Compressing seeds in {from_dir} and saving to {to_dir}")
    if (to_dir / compressed_file_name).exists():
        logger.info(f"Filename is already used, overwriting {compressed_file_name}")
    out_file = to_dir / compressed_file_name

    cctx = zstd.ZstdCompressor(level=19, threads=-1)
    with open(out_file, "wb") as f_out:
        with cctx.stream_writer(f_out) as compressor:
            with tarfile.open(fileobj=compressor, mode="w|") as tar:
                tar.add(from_dir, arcname=".")

class SeedsCollectorContext:
    def __init__(self, seed_share_dir: Path, interval: int = 60):
        self.lock = threading.RLock()
        self.seed_share_dir = seed_share_dir
        self.interval = interval
        self.files_state = {}
        self.dump_dir = None
        self.unique_id_to_harness_id = {}
        self.corpus_folders: dict[str, list[Path]] = {}
        self.corpus_folders_to_unique_id: dict[Path, str] = {}
        self.monitor_thread = None
        #self.harness_states = {}
        # A map from harness_id to the seeds folders composed from 
        # Path(SEED_SHARE_DIR) / "crs-multilang" / HARNESS_NAME 
        self.seed_share_scratch_dir = CRS_SCRATCH_DIR / "seeds_share"
        self.seed_share_scratch_dir.mkdir(parents=True, exist_ok=True)
        self.shared_seeds_folders = {}
        self.shared_dump_folders: dict[str, list[Path]] = {}
        self.node_idx = int(os.environ.get("NODE_IDX", 0))
        self.initial_corpus_dump_time = time.time()
        
        # watchdog
        self.observer = Observer()
        self.seeds_handler = SeedsHandler(self)
        self.watches = {}

    def add_watch(self, path: Path):
        logger.info(f"Adding watch on {path}")
        if path.exists():
            logger.info(f"{path} exists")
            watch = self.observer.schedule(self.seeds_handler, path, recursive=False)
            self.watches[path] = watch
            logger.info(f"Sending any existing seeds in {path} to ensembler by opening all existing seeds")
            count = 0
            for seed in path.iterdir():
                try:
                    if seed.is_file():
                        count += 1
                        event = FileClosedEvent(str(seed))
                        self.seeds_handler.on_closed(event)
                except Exception as e:
                    logger.error(f"Error triggering on_closed event: {e}")
            logger.info(f"{count} seeds already existed in {path}")
        else:
            logger.error(f"{path} does not exist")

    def remove_watch(self, path: Path):
        if path in self.watches:
            logger.info(f"Removing watch on {path}")
            self.observer.unschedule(self.watches[path])
            self.watches.pop(path)
        else:
            logger.error(f"Seeds collector was not watching {path}")

    def __scan_seed_share_dir(self, harness_id):
        """
        Remote NFS does not support fs events so we can only use dumb scanning
        Return all the file name last modification time.
        """
        if harness_id not in self.shared_seeds_folders:
            return {}
        seeds_dir = self.shared_seeds_folders[harness_id]
        if not seeds_dir.exists():
            logger.error(f"Seeds directory not created yet: {seeds_dir}")
            return {}
        logger.info(f"Polling {seeds_dir}")
        current_state = {}
        black_list = [".lafl_lock", ".tmp", ".metadata"]
        try:
            for file_path in seeds_dir.glob("*"):
                try:
                    if any(str(file_path).endswith(b) for b in black_list):
                        continue
                    file_mtime = file_path.stat().st_mtime
                    current_state[file_path] = file_mtime
                except FileNotFoundError:
                    continue
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
        return current_state

    def register_launch_announcement(self, harness_id: str, other_id: str, corpus_paths: list[Path], origin: str):
        with self.lock:
            unique_id = get_unique_id(other_id, origin)
            logger.info(f"Register launch announcement for {unique_id}")
            if unique_id not in self.unique_id_to_harness_id:
                self.unique_id_to_harness_id[unique_id] = harness_id
            else:
                logger.info(f"Harness {unique_id} already registered")
                return
            if unique_id not in self.corpus_folders:
                self.corpus_folders[unique_id] = corpus_paths
            
            for corpus_path in corpus_paths:
                if corpus_path not in self.corpus_folders_to_unique_id:
                    self.corpus_folders_to_unique_id[corpus_path] = unique_id

            if origin != GENERAL_ORIGIN:
                for corpus_path in corpus_paths:
                    self.add_watch(corpus_path)

            SEED_SHARE_DIR = os.environ.get("SEED_SHARE_DIR")

            if unique_id not in self.shared_seeds_folders:
                # NOTE need to use session_id as key
                seeds_sharing_dir = Path(SEED_SHARE_DIR) / "crs-multilang" / harness_id
                self.shared_seeds_folders[unique_id] = seeds_sharing_dir
                if origin == GENERAL_ORIGIN:
                    # Don't wait here and block other registers
                    if not seeds_sharing_dir.exists():
                        logger.error(f"Seeds sharing directory not created yet: {seeds_sharing_dir}")
                self.files_state[unique_id] = {}

            if unique_id not in self.shared_dump_folders:
                dump_dir = Path(SEED_SHARE_DIR) / "crs-userspace" / harness_id
                self.shared_dump_folders[unique_id] = dump_dir
                if not dump_dir.exists():
                    dump_dir.mkdir(parents=True, exist_ok=True)

    def save_seeds(self, unique_id, share_seeds: bool=True):
        """
        Save the seeds to the seed share directory.
        """
        dump_dir = self.shared_dump_folders[unique_id]
        if not dump_dir.exists():
            dump_dir.mkdir(parents=True, exist_ok=True)
        corpus_paths = self.corpus_folders[unique_id]
        logger.info(f"Saving our seeds to {dump_dir}")

        # get initial corpus dir
        harness_id = self.unique_id_to_harness_id[unique_id]
        general_unique_id = get_unique_id(harness_id, GENERAL_ORIGIN)
        general_corpus_paths = self.corpus_folders.get(general_unique_id)
        initial_corpus_dir = None
        if general_corpus_paths:
            initial_corpus_dir = Path(general_corpus_paths[0]).parent / 'initial_corpus'

        for corpus_dir in corpus_paths:
            if share_seeds:
                logger.info(f"Sharing seeds from {corpus_dir} to {dump_dir}")
                saving_seeds(corpus_dir, dump_dir)
            else:
                if initial_corpus_dir and initial_corpus_dir.exists():
                    logger.info(f"Saving seeds from {corpus_dir} to {initial_corpus_dir}, for next epoch")
                    saving_seeds(corpus_dir, initial_corpus_dir)

        # rsync to initial_corpus so that fuzzer restarts can recover better
        if GENERAL_ORIGIN in unique_id:
            initial_corpus_dir = Path(corpus_dir).parent / 'initial_corpus'
            logger.info(f"Saving seeds to initial_corpus at {initial_corpus_dir}")
            saving_seeds(dump_dir, initial_corpus_dir)

            # every 10 intervals, compress the initial_corpus and save it
            if time.time() - self.initial_corpus_dump_time > 10 * self.interval:
                compressed_file_dump_dir = LARGE_DATA_DIR / "seeds_collector" / "initial_corpus"
                compressed_file_dump_dir.mkdir(parents=True, exist_ok=True)
                compress_and_save_seeds(initial_corpus_dir, compressed_file_dump_dir, harness_id)
                self.initial_corpus_dump_time = time.time()

    def process_seed_additions(self, input_message: FuzzerSeeds):
        """
        Process seed additions.
        """
        if self.node_idx != 0:
            return

        for seed in input_message.data:
            # Create directory if it doesn't exist

            # Compute checksum and write seed to file
            hasher = hashlib.blake2b()
            hasher.update(seed)
            checksum = hasher.hexdigest()
            
            seed_path = self.seed_share_scratch_dir / checksum
            seed_path.write_bytes(seed)
            logger.info(f"Wrote seed with checksum {seed_path}")
            # rsync to dump dir with --ignore-existing

        dump_dir = Path(SEED_SHARE_DIR) / 'crs-userspace' / input_message.harness_id
        if not dump_dir.exists():
            dump_dir.mkdir(parents=True, exist_ok=True)
        
        subprocess.run(["rsync", "-a", "--ignore-existing", str(seed_path), str(dump_dir)], check=True)
        logger.info(f"Synced seed {seed_path} to {dump_dir}")

    def one_seed_handler(self, path, unique_id):
        """
        Handle a seed file.
        """
        send_seed_suggestions(unique_id, [Path(path)])

    def batch_seeds_handler(self, file_paths: list[Path], unique_id):
        """
        Handle a batch of seed files.
        """
        send_seed_suggestions(unique_id, file_paths)

    def __monitor_seeds(self):
        while True:
            with self.lock:
                if self.unique_id_to_harness_id.keys():
                    for unique_id, harness_id in self.unique_id_to_harness_id.items():
                        logger.info(f"Polling seeds folders for {unique_id}")
                        current_state = self.__scan_seed_share_dir(unique_id)
                        unique_id_state = self.files_state[unique_id]
                        added_files = [f for f in current_state if f not in unique_id_state]
                        modified_files = [
                            f
                            for f in current_state
                            if f in unique_id_state and current_state[f] != unique_id_state[f]
                        ]

                        blist = [".lafl_lock", ".tmp", ".metadata"]
                        seed_paths = [Path(f) for f in added_files + modified_files if not any(str(f).endswith(b) for b in blist)]
                        if len(seed_paths) > 0:
                            self.batch_seeds_handler(seed_paths, harness_id)
                        else:
                            logger.info("No new seeds found")

                        # update state
                        self.files_state[unique_id] = current_state

                        logger.info(f"Saving our seeds to crs-userpace")
                        # Only directly share seeds from general fuzzer
                        self.save_seeds(unique_id, share_seeds=(GENERAL_ORIGIN in unique_id))
                        logger.info(f"** heartbeat ** -> monitoring {self.shared_seeds_folders.get(unique_id)}")

                else:
                    logger.info("No active harnesses")
            time.sleep(self.interval)

    def start_monitoring(self):
        if self.monitor_thread is None:
            logger.info(f"Starting to monitor seeds folders under {self.seed_share_dir}")
            self.monitor_thread = threading.Thread(target=self.__monitor_seeds)
            self.monitor_thread.start()
            logger.info("Starting watchdog and seed processing thread")
            self.seeds_handler.process_seeds_thread.start()
            self.observer.start()
        else:
            logger.info("Monitoring already started")

    def deactivate_harness(self, harness_id: str, origin: str):
        with self.lock:
            unique_id = get_unique_id(harness_id, origin)
            if unique_id not in self.unique_id_to_harness_id:
                logger.info(f"Harness {unique_id} not registered")
                return
            logger.info(f"Stopping monitoring {self.shared_seeds_folders[unique_id]}")
            
            if origin != GENERAL_ORIGIN:
                for corpus_path in self.corpus_folders[unique_id]:
                    self.remove_watch(corpus_path)
                    self.corpus_folders_to_unique_id.pop(corpus_path)
            self.corpus_folders.pop(unique_id)
            self.unique_id_to_harness_id.pop(unique_id)
            self.shared_seeds_folders.pop(unique_id)
            self.shared_dump_folders.pop(unique_id)


class SeedsHandler(FileSystemEventHandler):
    def __init__(self, seeds_collector_ctx: SeedsCollectorContext, interval: int = 60, batch_size: int = BATCH_SIZE, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.blist = [".lafl_lock", ".tmp", ".metadata"]
        self.seeds_collector_ctx = seeds_collector_ctx
        self.pending_seeds = dict()
        self.pending_seeds_len = 0
        self.interval = interval
        self.batch_size = batch_size
        self.process_batch_event = threading.Event()
        self.last_processed = time.time()
        self.process_seeds_thread = threading.Thread(target=self._process_pending_seeds)

    def on_closed(self, event: FileClosedEvent):
        if event.is_directory:
            return
        
        if any(event.src_path.endswith(b) for b in self.blist):
            return

        path = Path(os.fsdecode(event.src_path))
        with self.seeds_collector_ctx.lock:
            unique_id = self.seeds_collector_ctx.corpus_folders_to_unique_id[path.parent]
            if unique_id not in self.pending_seeds:
                logger.info(f"Adding {unique_id} to pending seeds dictionary")
                self.pending_seeds[unique_id] = set()
            try: # whatever handling
                self.pending_seeds[unique_id].add(path.read_bytes())
                self.pending_seeds_len += len(path.read_bytes())
                if self.pending_seeds_len >= self.batch_size:
                    self.process_batch_event.set()
            except FileNotFoundError:
                pass

    def _process_pending_seeds(self):
        while True:
            self.process_batch_event.wait(timeout=self.interval)
            with self.seeds_collector_ctx.lock:
                logger.info(f"** watchdog heartbeat ** -> {len(self.seeds_collector_ctx.watches)} watches")
                for unique_id, seeds in self.pending_seeds.items():
                    if len(seeds) == 0:
                        continue
                    data = FuzzerSeeds()
                    harness_id = self.seeds_collector_ctx.unique_id_to_harness_id[unique_id]
                    data.harness_id = harness_id
                    data.origin = get_origin(unique_id) # "seeds_collector"
                    data.data.extend(list(seeds))
                    logger.info(f"Sending {len(data.data)} seeds to ensembler")
                    for handler in logging.getLogger().handlers:
                        handler.flush()
                    global kafka_producer
                    kafka_producer.send_message(data)
                self.last_processed = time.time()
                self.process_batch_event.clear()
                for unique_id in self.pending_seeds.keys():
                    self.pending_seeds[unique_id] = set()
                self.pending_seeds_len = 0
