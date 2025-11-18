import os
import sys
import time
import json
import redis
import requests
import threading
import subprocess
import signal
from loguru import logger

from uuid import uuid4, UUID
from pathlib import Path

from my_crs.task_server.models.types import (
    Task,
    TaskDetail,
    SARIFBroadcast,
    SARIFBroadcastDetail,
)
from my_crs.crs_manager.k8s_manager import K8sManager
from my_crs.crs_manager.crs_types import TaskStatus, State
from my_crs.crs_manager.crs_template import TEMPLATES
from my_crs.crs_manager.budget import reset_budgets, return_all_budget
from my_crs.crs_manager.log_config import setup_logger
setup_logger()

from libCRS import install_otel_logger



# TODO: add error handling
# TODO: migrate to pods -> update templates

TARBALL_DIR = Path("/tarball-fs")

# node name
NODE_NAME = os.getenv("NODE_NAME")

# Redis to task status
redis_endpoint = os.getenv("CRS_REDIS_ENDPOINT")

# Logger
signal.signal(signal.SIGCHLD, signal.SIG_IGN)


def wait_for_redis(url):
    while True:
        try:
            r = redis.from_url(url, decode_responses=True)
            r.ping()
            return r
        except redis.exceptions.ConnectionError:
            time.sleep(1)

def wait_litellm(url):
    url = f"{url}/health/liveness"
    while True:
        try:
            r = requests.get(url)
            if r.ok:
                return True
        except:
            pass

def create_llm_key_for_crs_sarif():
    url = os.getenv("LITELLM_PATCH_URL")
    wait_litellm(url)
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/key/generate"
    budget = int(os.getenv("CRS_SARIF_LLM_BUDGET"))
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "max_budget": budget,
    }
    for _ in range(10):
        try:
            r = requests.post(url, headers=headers, json=data)
            if r.ok:
                r = r.json()
                return r["key"]
        except Exception as e:
            logger.error(f"Error creating LLM key: {e}")
            time.sleep(5)
    return "ERROR_LLM_KEY"

class CRSManager:
    def __init__(self, init=False):
        # Redis for status
        self.redis_client = wait_for_redis(redis_endpoint)
        self.k8s = K8sManager(self.redis_client, TEMPLATES)
        with self.redis_client.lock("CRS_SARIF_LLM_KEY_LOCK"):
            self.crs_sarif_llm_key = self.redis_client.get("CRS_SARIF_LLM_KEY")
            if self.crs_sarif_llm_key == None:
                self.crs_sarif_llm_key = create_llm_key_for_crs_sarif()
                self.redis_client.set("CRS_SARIF_LLM_KEY", self.crs_sarif_llm_key)

    def error(self, msg):
        logger.error(f"[CRSManager] {msg}")

    def info(self, msg):
        logger.info(f"[CRSManager] {msg}")

    def invoke_process_task(self, task: Task):
        msg_id = task.message_id
        self.info(f"Get Task request: {msg_id}")
        self.redis_client.set(f"msg_{msg_id}", task.json())
        cmd = [
            "python3",
            "-m",
            "my_crs.crs_manager.crs_manager",
            "process_task",
            str(msg_id),
        ]
        subprocess.Popen(
            cmd,
            start_new_session=True,
            cwd="/app",
        )

    def invoke_cancel_task(self, task_id: UUID, deadline: int):
        cmd = [
            "python3",
            "-m",
            "my_crs.crs_manager.crs_manager",
            "cancel_task",
            str(task_id),
            str(deadline),
        ]
        subprocess.Popen(
            cmd,
            start_new_session=True,
            cwd="/app",
        )

    def invoke_cancel_task_all(self, deadline: int):
        for task_status in self.__list_task_status():
            if task_status.state != "canceled":
                self.invoke_cancel_task(task_status.detail.task_id, deadline)

    def invoke_process_sarif(self, sarif: SARIFBroadcast):
        msg_id = sarif.message_id
        self.info(f"Get SARIFBroadcast request: {msg_id}")
        self.redis_client.set(f"msg_{msg_id}", sarif.json())
        cmd = [
            "python3",
            "-m",
            "my_crs.crs_manager.crs_manager",
            "process_sarif",
            str(msg_id),
        ]
        subprocess.Popen(
            cmd,
            start_new_session=True,
            cwd="/app",
        )

    def main_process_task(self, task_msg_id: str):
        task = Task.model_validate_json(
            self.redis_client.get(f"msg_{task_msg_id}")
        )
        self.__process_task(task)

    def main_process_sarif(self, sarif_msg_id: str):
        sarif = SARIFBroadcast.model_validate_json(
            self.redis_client.get(f"msg_{sarif_msg_id}")
        )
        self.__process_sarif(sarif)

    def main_cancel_task(self, task_id: UUID, deadline: int):
        now = int(time.time())
        self.info(
            f"We will cancel task {task_id} at deadline: {deadline}, now {now}"
        )
        if now < deadline:
            self.info(f"Sleeping for {deadline - now} seconds")
            time.sleep(deadline - now)
        self.k8s.cancel_task(task_id)

    def __process_task(self, task: Task):
        task_ids = []
        for task_detail in task.tasks:
            task_id = self.__get_task_id(task_detail)
            os.makedirs(TARBALL_DIR / task_id, exist_ok=True)
            with open(TARBALL_DIR / task_id / "metadata.json", "w") as f:
                f.write(json.dumps(task_detail.metadata))

            os.environ["CRS_TASK_METADATA_JSON"] = str(
                TARBALL_DIR / task_id / "metadata.json"
            )
            install_otel_logger()

            task_id = self.__process_one_task(task_detail)

            os.unsetenv("CRS_TASK_METADATA_JSON")

            if task_id != None:
                task_ids.append(task_id)
        return task_ids

    def __process_one_task(self, task_detail: TaskDetail) -> str | None:
        """
        return task_id
        """
        task_id = self.__get_task_id(task_detail)
        task_status = self.__get_task_status(task_id)
        if task_status != None:
            if task_status.state != "canceled":
                self.error(
                    f"Task {task_id} already processed and in {task_status.state}. Ignoring..."
                )
                return None

        os.environ["TASK_ID"] = task_id
        self.info(
            f"{task_id}: project_name: {task_detail.project_name}, harness_included: {task_detail.harnesses_included}"
        )
        if not task_detail.harnesses_included:
            self.info(f"{task_id}: No harnesses included. Ignoring...")
            return_all_budget(task_id)
            return None

        self.info(f"Deploying resources for task {task_id}...")
        self.__create_task_status(task_detail)
        self.invoke_cancel_task(task_id, int(task_detail.deadline / 1000))
        cp_node_pool_name = self.k8s.create_or_reuse_cp_node_pool(task_detail)
        self.k8s.deploy_from_template(
            UUID(task_id),
            "cp-manager-node",
            cp_node_pool_name,
            1,
            task_detail,
            cp_node_pool_name,
            self.crs_sarif_llm_key,
        )
        return task_id

    def __process_sarif(self, sarifs: SARIFBroadcast):
        jobs = []
        for sarif in sarifs.broadcasts:
            t = threading.Thread(target=self.__process_one_sarif, args=(sarif,))
            jobs.append(t)
            t.start()
        for t in jobs:
            t.join()

    def __process_one_sarif(self, sarif: SARIFBroadcastDetail):
        task_id = sarif.task_id
        url = f"http://cp-manager-{task_id}/task/sarif/"
        data = {
            "metadata": sarif.metadata,
            "sarif": sarif.sarif,
            "sarif_id": str(sarif.sarif_id),
        }
        while True:
            try:
                self.info(f"Send SARIF request to {url}")
                r = requests.post(url, json=data, timeout=10)
                if r.ok:
                    self.info(f"{url}: 200 OK")
                    break
            except Exception as e:
                self.info(str(e))
            time.sleep(10)

    def __get_task_id_redis_key(self, task_id: str) -> str:
        return f"task_{task_id}"

    def __get_task_status(self, task_id: str) -> TaskStatus:
        key = self.__get_task_id_redis_key(task_id)
        task_status_raw = self.redis_client.get(key)
        if task_status_raw == None:
            return None
        try:
            return TaskStatus.model_validate_json(task_status_raw)
        except:
            return None

    def __list_task_status(self) -> list[TaskStatus]:
        keys = self.redis_client.keys("task_*")
        task_statuses = []
        for key in keys:
            task_status_raw = self.redis_client.get(key)
            task_statuses.append(
                TaskStatus.model_validate_json(task_status_raw)
            )
        return task_statuses

    def __get_task_id(self, task_detail: TaskDetail) -> str:
        return str(task_detail.task_id)

    def __create_task_status(self, task_detail: TaskDetail):
        task_id = self.__get_task_id(task_detail)
        task_status = TaskStatus(
            detail=task_detail,
            vuln_ids={},
            state=State.Running,
            cp_manager_service=f"http://cp-manager-{task_id}:80",
        )
        key = self.__get_task_id_redis_key(task_id)
        self.redis_client.set(key, task_status.model_dump_json())
        # state -> number of tasks in status
        self.redis_client.incr("running")

    def count_state(self, key) -> int:
        return int(self.redis_client.get(key) or 0)

    def reset_stats(self):
        states = [
            "canceled",
            "errored",
            "failed",
            "pending",
            "running",
            "succeeded",
            "waiting",
        ]
        for state in states:
            self.redis_client.set(state, 0)
        # Store the current timestamp (in ms) when stats are reset
        self.redis_client.set("since", int(time.time() * 1000))
        self.info("Reset all status stats")
        self.info("Reset all budgets")
        reset_budgets()


if __name__ == "__main__":
    crs_manager = CRSManager()
    if sys.argv[1] == "process_task":
        crs_manager.main_process_task(sys.argv[2])
    elif sys.argv[1] == "process_sarif":
        crs_manager.main_process_sarif(sys.argv[2])
    elif sys.argv[1] == "cancel_task":
        os.environ["TASK_ID"] = sys.argv[2]
        crs_manager.main_cancel_task(UUID(sys.argv[2]), int(sys.argv[3]))
