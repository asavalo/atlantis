import asyncio
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import shlex
import subprocess
import sys
import threading
import time
import re
import traceback
import hashlib
import glob
import zlib
import yaml as pyyaml
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from libatlantis.constants import ARTIFACTS_DIR, KAFKA_SERVER_ADDR, CRASHING_SEED_SUGGESTIONS_TOPIC
from libatlantis.protobuf import FuzzerLaunchAnnouncement, FuzzerSeeds, SUCCESS
from libatlantis.service_utils import configure_logger
from libCRS.otel import install_otel_logger, OpenTelemetryHandler
from libCRS.util import run_cmd
from libmsa.kafka.producer import Producer

logger = logging.getLogger(__name__)

GENERAL_ORIGIN = "general_fuzzing"
DIRECTED_ORIGIN = "directed_fuzzing"
SARIF_ORIGIN = "sarif"
BATCH_SIZE = 500000 # 0.5MB

def b2b_checksum(path, chunk_size=1048576):  # 1MB chunks
    hasher = hashlib.blake2b()
    with open(path, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_launch_id(launch_ann):
    # Use a unique field or hash relevant fields
    return launch_ann.nonce 

def get_unique_id(harness_id, origin):
    return f"{harness_id}-{origin}"

class CrashCollectorContext:
    def __init__(self):
        self.lock = threading.Lock()
        self.submitted_crashes = set()
        self.loop = None
        self.info = {}
        self.nretry = 2
        self.seen_seeds = set()
        self.files_state = {}
        self.unique_id_to_harness_id = {}
        self.crashes_paths: dict[str, list[Path]] = {}
        self.monitor_thread = None
        self.seen_checksums = {}
        self.MAX_CHECKSUMS = 100
        self.node_idx = int(os.environ.get("NODE_IDX", 0))
        self.interval = 10

    def activate_harness(self, harness_id: str, crashes_paths: list[Path], origin: str, session_id=None):
        with self.lock:
            if session_id:
                unique_id = get_unique_id(session_id, origin)
            else:
                unique_id = get_unique_id(harness_id, origin)
            if unique_id not in self.unique_id_to_harness_id:
                logger.info(f"Register fuzzing session for {unique_id}")
                self.unique_id_to_harness_id[unique_id] = harness_id
                self.files_state[unique_id] = {}
            else:
                logger.error(f"{unique_id} is active")
                return
            if unique_id not in self.crashes_paths:
                logger.info(f"Register {unique_id}, crashes_path : {crashes_paths}")
                self.crashes_paths[unique_id] = crashes_paths

    def deactivate_harness(self, harness_id: str, origin: str):
        with self.lock:
            unique_id = get_unique_id(harness_id, origin)
            if unique_id in self.unique_id_to_harness_id:
                logger.info(f"Deregister {unique_id}")
                self.unique_id_to_harness_id.pop(unique_id)
                self.crashes_paths.pop(unique_id)
            else:
                logger.error(f"{unique_id} is already not active")

    def seed_batch_crashes(self, harness_id: str, file_paths: list[Path]):
        if file_paths:
            byte_len = 0
            data_batch = []
            for fp in file_paths:
                data_batch.append(fp.read_bytes())
                byte_len += len(fp.read_bytes())
                if byte_len >= BATCH_SIZE:
                    data = FuzzerSeeds()
                    data.harness_id = harness_id
                    data.origin = "crash_collector"
                    data.data.extend(data_batch)
                    logger.info(f"{len(data.data)} new crash seeds for {harness_id}")
                    for handler in logging.getLogger().handlers:
                        handler.flush()
                    kafka_producer = Producer(KAFKA_SERVER_ADDR, CRASHING_SEED_SUGGESTIONS_TOPIC)
                    kafka_producer.send_message(data)
                    logger.info(f"[{harness_id}] Sent {len(data.data)} crash seeds to ensembler")
                    data_batch = []
                    byte_len = 0

            # send last batch if any
            if data_batch:
                data = FuzzerSeeds()
                data.harness_id = harness_id
                data.origin = "crash_collector"
                data.data.extend(data_batch)
                logger.info(f"{len(data.data)} new crash seeds for {harness_id}")
                for handler in logging.getLogger().handlers:
                    handler.flush()
                kafka_producer = Producer(KAFKA_SERVER_ADDR, CRASHING_SEED_SUGGESTIONS_TOPIC)
                kafka_producer.send_message(data)
                logger.info(f"[{harness_id}] Sent {len(data.data)} crash seeds to ensembler")

    def __scan_crashes_dir(self, crashes_dir: Path):
        """
        Remote NFS does not support fs events so we can only use dumb scanning
        """
        current_state = {}
        black_list = [".lafl_lock", ".tmp", ".metadata"]
        if not crashes_dir.exists():
            logger.error(f"Crash directory not created yet: {crashes_dir}")
            return current_state
        try:
            for file_path in crashes_dir.glob("*"):
                try:
                    if any(str(file_path).endswith(b) for b in black_list):
                        continue
                    if re.search(r'-\d+$', str(file_path)):
                        continue
                    file_mtime = file_path.stat().st_mtime
                    current_state[file_path] = file_mtime
                except FileNotFoundError:
                    continue
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
        return current_state

    def __monitor_crashes(self):
        while True:
            with self.lock:
                if self.unique_id_to_harness_id.keys():
                    for unique_id, harness_id in self.unique_id_to_harness_id.items():
                        crashes_paths = self.crashes_paths.get(unique_id)
                        if not crashes_paths:
                            logger.error("No crashes directory to monitor")
                            continue
                        
                        existing_crashes_paths = []
                        current_state = {}
                        for crashes_dir in crashes_paths:
                            if not crashes_dir.exists():
                                logger.info(f"Waiting for crash directory to be created: {crashes_dir}")
                            else:
                                existing_crashes_paths.append(crashes_dir)
                                current_state |= self.__scan_crashes_dir(crashes_dir)
                        logger.info(f"Polling {unique_id} at {len(existing_crashes_paths)} directories")

                        unique_id_state = self.files_state[unique_id]
                        added_files = [f for f in current_state if f not in unique_id_state]
                        modified_files = [
                            f
                            for f in current_state
                            if f in unique_id_state and current_state[f] != unique_id_state[f]
                        ]

                        # deduplicate checksum
                        unique_paths = []
                        for path in added_files + modified_files:
                            checksum = b2b_checksum(path)
                            
                            # If this checksum is not in our tracked set, it's unique
                            if checksum not in self.seen_checksums:
                                unique_paths.append(path)
                            
                            # Update frequency counter for this checksum
                            if checksum in self.seen_checksums:
                                self.seen_checksums[checksum] += 1
                            elif len(self.seen_checksums) < self.MAX_CHECKSUMS:
                                # We have room to add this new checksum
                                self.seen_checksums[checksum] = 1
                            else:
                                # Find the least frequent checksum
                                min_checksum = min(self.seen_checksums, key=self.seen_checksums.get)
                                min_count = self.seen_checksums[min_checksum]
                                
                                # Only replace if the new checksum has potential to be more frequent
                                if 1 >= min_count:  # New checksum starts with count 1
                                    del self.seen_checksums[min_checksum]
                                    self.seen_checksums[checksum] = 1
                        
                        if len(unique_paths) > 0:
                            self.seed_batch_crashes(harness_id, unique_paths)

                        # update state
                        self.files_state[unique_id] = current_state
                else:
                    logger.info("No active harnesses")
            time.sleep(self.interval)

    def start_monitoring(self):
        if not self.monitor_thread:
            logger.info(f"Starting to monitor crash folders")
            self.monitor_thread = threading.Thread(target=self.__monitor_crashes)
            self.monitor_thread.start()
