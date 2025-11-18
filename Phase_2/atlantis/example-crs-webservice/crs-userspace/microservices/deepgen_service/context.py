import logging
import os
import time
import asyncio
from threading import Lock, Thread
from multiprocessing import Process
from libCRS.util import run_cmd
from pathlib import Path
from libatlantis.protobuf import (
    DeepGenRequest,
    FuzzerRunResponse,
    FuzzerStopResponse,
    FuzzerLaunchAnnouncement,
    HarnessPrioritization,
)
from .task_models import OneShotTaskParams, DiffAnalysisTaskParams, CancelTaskParams
from .dealer_manager import DealerManager
from multiprocessing import Process, Manager

logger = logging.getLogger(__name__)

from .config import TASK_QUEUE_ADDR, ACK_QUEUE_ADDR
from .ipc_utils import AsyncSender, SyncSender
from .worker import start_engine_worker


TEMPFS_DIR = os.environ.get("ENSEMBLER_TMPFS", "/tmpfs")

class DeepGenContext:
    def __init__(self):
        self.lock = Lock()
        self.node_idx = int(os.environ.get("NODE_IDX", 0))
        # self.sender = SyncSender(
        #     task_addr=TASK_QUEUE_ADDR,
        #     ack_addr=ACK_QUEUE_ADDR,
        #     timeout=15,
        #     max_retries=6,
        # )
        self.project_info = None
        self.worker_process = None
        self.manager = Manager()
        self.disabled_harnesses = self.manager.dict()
        self.current_harness = self.manager.dict()
        self.dealer_manager = DealerManager(router_addr="ipc:///tmp/ipc/haha")

    def start_dealer(self, harness_id: str):
        if harness_id in self.disabled_harnesses:
            return
        self.dealer_manager.start_dealer(harness_id)

    def stop_dealer(self, harness_id: str):
        if harness_id in self.disabled_harnesses:
            return
        self.dealer_manager.stop_dealer(harness_id)

    def handle_libfuzzer_fallback(self, input_message: FuzzerLaunchAnnouncement):
        with self.lock:
            self.start_dealer(input_message.harness_id)

    def handle_harness_prioritization(self, input_message: HarnessPrioritization):
        with self.lock:
            if bool(input_message.enable):
                self.disabled_harnesses.pop(input_message.harness_id, None)
            else:
                self.disabled_harnesses[input_message.harness_id] = True

    def is_running(self):
        with self.lock:
            return self.worker_process is not None

    def wait_worker(self):
        for i in range(200):
            if self.worker_process is not None:
                logger.info("Good, worker is running")
                break
            time.sleep(10)
            logger.info(f"Waiting for worker to start ({i}/200)")

    def clean_shm(self):
        if self.project_info is None:
            logger.info("[clean_shm] No project info, skipping")
            return
        run_cmd(
            [
                "sh",
                "-c",
                f"rm $(grep -rl {self.project_info['shm_label']} /dev/shm) || true",
            ]
        )

    def start_worker(self):
        self.worker_process = Process(
            target=start_engine_worker, args=(self.project_info, self.current_harness, self.disabled_harnesses)
        )
        self.worker_process.start()

        if self.worker_process is not None:
            logger.info("Worker started")
        else:
            logger.error("Worker failed to start")

    def handle_engine_start(self, input_message: DeepGenRequest):
        with self.lock:
            if self.worker_process is not None:
                logger.info("Engine is already running, skipping")
                return
            
            time.sleep(5)
            workdir = (
                Path(TEMPFS_DIR)
                / f"deepgen_workdir_{self.node_idx}"
            )
            workdir.mkdir(exist_ok=True)
            self.project_info = {
                "ossfuzz_home": input_message.oss_fuzz_path,
                "project_name": input_message.cp_name,
                "local_repo_dir": input_message.cp_src_path,
                "mode": input_message.mode,
                "cp_mount_path": input_message.cp_mount_path,
                "workdir": workdir,
                "cores": list(input_message.cores),
                "shm_label": f"dg_{input_message.cp_name.replace('/', '_')}_{self.node_idx}",
            }
            self.clean_shm()
            self.start_worker()

    def handle_engine_stop(self, input_message: DeepGenRequest):
        with self.lock:
            if self.worker_process is None:
                logger.info("Engine is not running, skipping")
                return
            
            time.sleep(5)
            logger.info("Engine stopping")
            self.worker_process.kill()
            self.worker_process.join(timeout=5)
            self.clean_shm()
            self.worker_process = None
            self.project_info = None

    def handle_fuzzer_run(self, input_message: FuzzerRunResponse):
        with self.lock:
            self.wait_worker()
            harness_id = input_message.harness_id
            if harness_id in self.disabled_harnesses:
                logger.info(f"Harness {harness_id} is disabled, skipping")
                return

            logger.info(f"==> handling {harness_id} in node {self.node_idx}")
            self.current_harness["harness_id"] = harness_id
            time.sleep(1)
            

    def handle_fuzzer_stop(self, input_message: FuzzerStopResponse):
        with self.lock:
            self.wait_worker()
            self.current_harness["disable_harness_id"] = str(input_message.harness_id)