import base64
import json
import logging
import os
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, Request

SERVER_PORT = 8088
DEFAULT_LOCAL_CRS_PATCH_SERVER = "http://localhost:8000"

system_a_thread = None


def get_target_list() -> List[str]:
    targets = os.environ.get("DETECTIONS", None)
    if targets:
        return targets.split(",")

    raise Exception("DETECTIONS is not set")


detections = get_target_list()
os.makedirs("logs", exist_ok=True)


def get_logger(name: str, log_file: Optional[Path] = None):
    logger = logging.getLogger(name)
    # Clear any existing handlers
    logger.handlers = []

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(file_handler)

    # Console handler for stdout output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )
    logger.addHandler(console_handler)

    logger.setLevel(logging.INFO)
    return logger


def run(cmd: str):
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        raise Exception(f"Failed to run {cmd}: {result.stderr}")
    return result.returncode, result.stdout, result.stderr


def start_system_a():
    for target in detections:
        kill_docker()
        target = Path(target)
        task_id = str(uuid.uuid4())
        logger = get_logger("crs-test-server", log_file=Path(f"logs/{target.name}.log"))
        logger.info(f"Starting server for target: {target}")
        logger.info(f"Task ID: {task_id}")

        ## Make tarballs
        try:
            logger.info(f"Making tarballs for {target}")
            return_code, stdout, stderr = run(
                f"uv run python scripts/crs_test/make_tarballs.py {target}"
            )

            if return_code != 0:
                logger.error(f"Failed to make tarballs for {target}")
                raise Exception(f"Failed to make tarballs for {target}: {stderr}")

        except Exception as e:
            logger.error(f"Failed to make tarballs for {target}: {e}")
            continue

        ## Run docker
        docker_cmd_pattern = r"\./docker-run\.sh.*"
        docker_cmd_match = re.search(docker_cmd_pattern, stdout)
        if docker_cmd_match:
            logger.info("Successfully made tarballs and ready to run docker")
            docker_cmd = docker_cmd_match.group(0)
            docker_cmd += f" -k -d -t {task_id} -e VAPI_HOST=http://host.docker.internal:{SERVER_PORT}"
        else:
            logger.error(f"Unexpected output from make_tarballs: {stdout}")
            raise Exception("Failed to get expected output from make_tarballs")
        logger.info(f"Running docker command: {docker_cmd}")
        try:
            return_code, stdout, stderr = run(docker_cmd)
            if return_code != 0:
                logger.error(f"Failed to run docker for {target}: {stderr}")
                raise Exception(f"Failed to run docker for {target}: {stderr}")
        except Exception as e:
            logger.error(f"Failed to run docker for {target}: {e}")
            save_container_logs(target.name, task_id, logger)
            continue

        ## Wait for server to be ready
        logger.info("Waiting for server to be ready")
        wait_for_server(logger, DEFAULT_LOCAL_CRS_PATCH_SERVER)

        ## Test requests
        logger.info(f"Server is running for {target}")
        try:
            # Request patch
            pov_id = str(uuid.uuid4())
            return_code, stdout, stderr = run(
                f"uv run python scripts/crs_test/test_requests.py {target} --pov-id {pov_id}"
            )
            if return_code != 0:
                logger.error(f"Failed to request patch for {target}: {stderr}")
                raise Exception(f"Failed to request patch for {target}: {stderr}")
        except Exception as e:
            logger.error(f"Failed to request patch for {target}: {e}")
            save_container_logs(target.name, task_id, logger)
            continue

        ## Wait for patch to be processed
        logger.info(f"Waiting for patch {pov_id} to be processed")
        last_log_time = time.time()
        while True:
            try:
                response = requests.get(
                    f"{DEFAULT_LOCAL_CRS_PATCH_SERVER}/v1/patch/{pov_id}/"
                )
                if (
                    response.status_code == 200
                    and response.json()["status"] != "processing"
                    and response.json()["status"] != "waiting"
                ):
                    logger.info(f"Patch {pov_id} is done: {response.json()}")
                    break
                current_time = time.time()
                if current_time - last_log_time >= 180:  # Log every 3 minutes
                    logger.info(f"Waiting for patch {pov_id} to be processed")
                    last_log_time = current_time
            except Exception as e:
                logger.error(f"Failed to get patch status for {pov_id}: {e}")
                break

            time.sleep(10)

        ## Save container logs
        save_container_logs(target.name, task_id, logger)

    ## Kill docker
    kill_docker()
    print("All done")
    time.sleep(10)
    cleanup()


def save_container_logs(name: str, task_id: str, logger: logging.Logger):
    os.makedirs(f"logs/{name}", exist_ok=True)
    # Save main container logs
    containers: List[str] = []
    containers.append(f"crs-patch-main-{task_id}")
    for i in range(1, 5):
        containers.append(f"crs-patch-sub-{i}-{task_id}")

    # Save sub-node logs
    for container in containers:
        try:
            result = subprocess.run(
                f"docker logs {container}",
                capture_output=True,
                text=True,
                shell=True,
            )
            with open(f"logs/{name}/{container}.log", "w") as f:
                if result.stdout:
                    f.write(result.stdout)
                if result.stderr:
                    f.write(result.stderr)
        except Exception as e:
            logger.error(f"Error saving {container} logs: {e}")


def kill_docker():
    subprocess.run(
        "./docker-kill.sh",
        capture_output=True,
        text=True,
        shell=True,
    )


def wait_for_server(logger: logging.Logger, url: str):
    last_log_time = 0
    while True:
        try:
            requests.get(url)
            break
        except requests.exceptions.RequestException:
            pass

        current_time = time.time()
        if current_time - last_log_time >= 180:  # Log every 3 minutes
            logger.info("wait_for_server...")
            last_log_time = current_time

        time.sleep(10)  # Wait 30 seconds before next ping


def cleanup():
    if system_a_thread and system_a_thread.is_alive():
        system_a_thread.join(timeout=5)
    kill_docker()


def install_signal_handler():
    """Shutdown the uvicorn server gracefully"""
    import signal

    def signal_handler(sig: int, frame: Any):
        print("Shutting down server...")
        cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global system_a_thread
    install_signal_handler()
    system_a_thread = threading.Thread(target=start_system_a, daemon=True)
    system_a_thread.start()
    yield
    # Shutdown
    cleanup()


app = FastAPI(lifespan=lifespan)
submission_queue: queue.Queue[Dict[str, Any]] = queue.Queue()


FAKE_PATCH_ID = "123e4567-e89b-12d3-a456-426614174000"


@app.get("/")
def read_root():
    return {
        "patch_id": "123e4567-e89b-12d3-a456-426614174000",  # Example UUID
        "status": "accepted",
    }


# /submit/patch/123e4567-e89b-12d3-a456-426614174000


@app.get("/submit/patch/{patch_id}")
def submit_patch_get(patch_id: str):
    return {
        "patch_id": patch_id,
        "status": "passed",
    }


@app.post("/submit/patch/pov/{pov_id}")
async def submit_patch(pov_id: str, request: Request):
    # Get the request body
    body = await request.json()
    patched_again_pov_ids = body["patched_again_pov_ids"]
    patch = body["patch"]
    b64encoded_patch = base64.b64encode(patch.encode()).decode()
    # Create submission data
    submission_data = {
        "pov_id": pov_id,
        "patched_again_pov_ids": patched_again_pov_ids,
        "patch": b64encoded_patch,
    }

    # save submission data to file
    with open(f"logs/pov_{pov_id}.json", "w") as f:
        json.dump(submission_data, f)

    # Add to queue
    submission_queue.put(submission_data)

    return {
        "patch_id": "123e4567-e89b-12d3-a456-426614174000",  # Example UUID
        "status": "accepted",
    }
