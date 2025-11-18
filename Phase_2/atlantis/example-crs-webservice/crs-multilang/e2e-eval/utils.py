import asyncio
import os
import re
import shutil
import subprocess
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger

from litellm_utils import delete_key, generate_key, get_key_stats, save_key_stats


@asynccontextmanager
async def safe_subprocess(*args, timeout: Optional[float] = None, **kwargs):
    """
    Safe subprocess context manager that guarantees cleanup.

    Args:
        *args: Command and arguments
        timeout: Optional timeout for process termination
        **kwargs: Additional subprocess arguments

    Yields:
        subprocess.Process: The subprocess object
    """
    process = None
    try:
        process = await asyncio.create_subprocess_exec(*args, **kwargs)
        yield process
    finally:
        if process and process.returncode is None:
            # Graceful termination
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout or 10.0)
            except asyncio.TimeoutError:
                # Force kill if graceful termination fails
                process.kill()
                await process.wait()


async def run_subprocess_safe(
    *args, timeout: Optional[float] = None, **kwargs
) -> Tuple[int, bytes, bytes]:
    """
    Run subprocess safely with guaranteed cleanup.

    Returns:
        Tuple[returncode, stdout, stderr]
    """
    async with safe_subprocess(*args, timeout=timeout, **kwargs) as process:
        stdout, stderr = await process.communicate()
        return process.returncode, stdout, stderr


def fire_and_ignore(command: str, env: Dict[str, str] = None) -> bool:
    """Execute a command in the background without blocking."""
    try:
        # Use nohup to completely detach from parent process
        detached_cmd = f"nohup {command} &"

        # Use subprocess.run with proper file descriptor management
        result = subprocess.run(
            detached_cmd,
            shell=True,
            env=env or os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,  # Quick timeout just to start the process
        )

        return result.returncode == 0

    except Exception as e:
        logger.debug(f"Failed to fire command '{command}': {e}")
        return False


@dataclass
class JobInfo:
    """Job information for experiment execution"""

    target: str
    hash_str: str
    config_file: Path
    temp_multilang_root: Path
    cores_needed: int
    job_id: Optional[str] = None
    litellm_api_key: Optional[str] = None
    process_id: Optional[int] = None
    user_id: Optional[str] = None
    start_other_services: Optional[bool] = None

    def __post_init__(self):
        if self.job_id is None:
            self.job_id = create_job_id()

        if self.process_id is None:
            self.process_id = os.getpid()

        # Generate LiteLLM API key for this job (requires user_id to be set)
        if self.start_other_services:
            if self.litellm_api_key is None and self.user_id is not None:
                try:
                    self.litellm_api_key = generate_key(self.job_id, self.user_id)
                    logger.info(
                        f"Generated LiteLLM key for job {self.job_id} (process"
                        f" {self.process_id}, user {self.user_id})"
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to generate LiteLLM key for job {self.job_id}: {e}"
                    )
                    logger.warning("Proceeding without job-specific LiteLLM key")

    def to_dict(self):
        """Convert to dictionary for job queue"""
        return {
            "job_id": self.job_id,
            "target": self.target,
            "hash_str": self.hash_str,
            "config_file": self.config_file,
            "temp_multilang_root": self.temp_multilang_root,
            "cores_needed": self.cores_needed,
            "litellm_api_key": self.litellm_api_key,
            "process_id": self.process_id,
            "user_id": self.user_id,
            "start_other_services": self.start_other_services,
        }


class CPUSlotManager:
    """Simple CPU slot allocation manager"""

    def __init__(self, total_cores: int, cores_per_job: int, start_core: int = 0):
        self.cores_per_job = cores_per_job
        self.start_core = start_core
        max_slots = (total_cores - start_core) // cores_per_job
        self.available_slots = list(range(max_slots))
        self.allocated = {}  # job_id -> slot_id
        self.lock = asyncio.Lock()

        logger.info(
            f"CPU Manager: {max_slots} slots × {cores_per_job} cores (cores"
            f" {start_core}-{total_cores-1})"
        )

    async def allocate(
        self, job_id: str, cores_needed: int
    ) -> Optional[Tuple[int, int]]:
        """Allocate CPU cores for a job, returns (start_core, end_core) if successful"""
        # Calculate how many slots we need
        slots_needed = (cores_needed + self.cores_per_job - 1) // self.cores_per_job

        async with self.lock:
            if len(self.available_slots) >= slots_needed:
                allocated_slots = []
                for _ in range(slots_needed):
                    slot = self.available_slots.pop(0)
                    allocated_slots.append(slot)
                self.allocated[job_id] = allocated_slots

                # Calculate the actual core range
                start_core = self.start_core + (
                    min(allocated_slots) * self.cores_per_job
                )
                end_core = start_core + cores_needed - 1

                logger.debug(
                    f"Allocated {slots_needed} slots {allocated_slots} to job {job_id}"
                    f" for {cores_needed} cores ({start_core}-{end_core})"
                )
                return start_core, end_core
            else:
                logger.debug(
                    f"Not enough slots for job {job_id}: need {slots_needed} slots"
                    f" for {cores_needed} cores, have {len(self.available_slots)} slots"
                )
                return None

    async def release(self, job_id: str) -> bool:
        """Release all slots allocated to a job"""
        async with self.lock:
            if job_id in self.allocated:
                slots = self.allocated.pop(job_id)
                for slot in slots:
                    self.available_slots.append(slot)
                self.available_slots.sort()
                logger.debug(f"Released slots {slots} from job {job_id}")
                return True
            return False

    def get_cores(self, slot_id: int) -> Tuple[int, int]:
        """Get the core range for a slot"""
        start = self.start_core + (slot_id * self.cores_per_job)
        return start, start + self.cores_per_job - 1

    def get_status(self) -> Dict:
        """Get current slot status"""
        return {
            "available_slots": len(self.available_slots),
            "allocated_slots": len(self.allocated),
            "total_slots": len(self.available_slots) + len(self.allocated),
        }


class JobQueue:
    """Simple job queue manager"""

    def __init__(self, prevent_target_collision=False):
        self.pending = asyncio.Queue()
        self.running = {}  # job_id -> job_info
        self.completed = {}  # job_id -> job_info
        self.all_jobs = {}  # job_id -> job_info (tracks all jobs ever added)

        # Target collision prevention
        self.prevent_target_collision = prevent_target_collision
        self.running_targets = set()  # Set of currently running targets
        self.target_pending_queues = (
            {}
        )  # target -> list of pending jobs for that target

    async def add_job(self, job_info: Dict) -> None:
        """Add a job to the pending queue"""
        job_id = job_info["job_id"]
        self.all_jobs[job_id] = job_info
        await self.pending.put(job_info)
        logger.debug(f"Added job {job_id} to queue")

    async def get_next_job(self) -> Dict:
        """Get the next job from the queue"""
        return await self.pending.get()

    def mark_running(self, job_id: str, job_info: Dict) -> None:
        """Mark a job as running"""
        self.running[job_id] = job_info

    def mark_completed(self, job_id: str) -> None:
        """Mark a job as completed"""
        if job_id in self.running:
            job_info = self.running.pop(job_id)
            self.completed[job_id] = job_info
            logger.success(f"Job {job_id} completed")

    def get_status(self) -> Dict:
        """Get current queue status"""
        status = {
            "pending_jobs": self.pending.qsize(),
            "running_jobs": len(self.running),
            "completed_jobs": len(self.completed),
        }

        # Add target collision prevention status if enabled
        if self.prevent_target_collision:
            status.update(
                {
                    "target_collision_prevention": True,
                    "running_targets": len(self.running_targets),
                    "targets_with_queued_jobs": len(self.target_pending_queues),
                    "total_queued_jobs_for_targets": sum(
                        len(jobs) for jobs in self.target_pending_queues.values()
                    ),
                }
            )
        else:
            status["target_collision_prevention"] = False

        return status

    def is_empty(self) -> bool:
        """Check if queue is empty and no jobs are running"""
        return self.pending.empty() and len(self.running) == 0

    def get_pending_jobs(self) -> List[Dict]:
        """Get all pending jobs without removing them from queue"""
        pending_jobs = []
        temp_jobs = []

        # Extract all jobs from the queue
        while not self.pending.empty():
            try:
                job = self.pending.get_nowait()
                pending_jobs.append(job)
                temp_jobs.append(job)
            except asyncio.QueueEmpty:
                break

        # Put them back in the queue
        for job in temp_jobs:
            self.pending.put_nowait(job)

        return pending_jobs

    def get_all_jobs(self) -> List[Dict]:
        """Get all jobs from all states (pending, running, completed)"""
        all_jobs = []

        # Get pending jobs
        all_jobs.extend(self.get_pending_jobs())

        # Get running jobs
        all_jobs.extend(self.running.values())

        # Get completed jobs
        all_jobs.extend(self.completed.values())

        return all_jobs

    def is_target_running(self, target: str) -> bool:
        """Check if target is currently running"""
        if not self.prevent_target_collision:
            return False
        return target in self.running_targets

    def mark_target_running(self, target: str) -> None:
        """Mark a target as running"""
        if self.prevent_target_collision:
            self.running_targets.add(target)
            logger.debug(f"Target {target} marked as running")

    def mark_target_completed(self, target: str) -> None:
        """Mark a target as completed and dispatch next job for that target"""
        if not self.prevent_target_collision:
            return

        if target in self.running_targets:
            self.running_targets.remove(target)
            logger.debug(f"Target {target} marked as completed")

            # Check if there are pending jobs for this target
            if (
                target in self.target_pending_queues
                and self.target_pending_queues[target]
            ):
                next_job = self.target_pending_queues[target].pop(0)
                # Put the job back in the main queue for processing
                self.pending.put_nowait(next_job)
                logger.info(
                    f"Dispatched next job for target {target}: {next_job['job_id']}"
                )

                # Clean up empty queue
                if not self.target_pending_queues[target]:
                    del self.target_pending_queues[target]

    async def queue_job_for_target(self, target: str, job_info: Dict) -> None:
        """Queue a job for a target that's currently running"""
        if not self.prevent_target_collision:
            await self.add_job(job_info)
            return

        if target not in self.target_pending_queues:
            self.target_pending_queues[target] = []

        self.target_pending_queues[target].append(job_info)
        logger.info(
            f"Queued job {job_info['job_id']} for target {target} (target busy)"
        )


async def find_completed_jobs_and_monitors(
    running_job_ids: List[str],
) -> Tuple[List[str], Dict[str, List[int]]]:
    """Find completed jobs AND their monitoring processes in single ps call"""
    if not running_job_ids:
        return [], {}

    try:
        returncode, stdout, stderr = await run_subprocess_safe(
            "ps",
            "axe",
            "-o",
            "pid,command",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            timeout=10.0,
        )

        if returncode != 0:
            logger.warning(f"ps command failed: {stderr.decode()}")
            return [], {}

        active_jobs = set()
        monitoring_pids = {}  # job_id -> [monitor_pids]

        # Single pass through ps output
        for line in stdout.decode().split("\n"):
            if "CRS_JOB_ID=" in line:
                job_id_match = re.search(r"CRS_JOB_ID=([a-f0-9-]+)", line)
                if job_id_match:
                    job_id = job_id_match.group(1)
                    parts = line.strip().split()
                    if parts:
                        try:
                            pid = int(parts[0])

                            if "CRS_MONITOR_TYPE=mpstat" in line:
                                # This is a monitoring process
                                if job_id not in monitoring_pids:
                                    monitoring_pids[job_id] = []
                                monitoring_pids[job_id].append(pid)
                            else:
                                # This is a main job process
                                active_jobs.add(job_id)
                        except (ValueError, IndexError):
                            continue

        # Find completed jobs
        completed = [job_id for job_id in running_job_ids if job_id not in active_jobs]
        if completed:
            logger.debug(f"Found {len(completed)} completed jobs")

        return completed, monitoring_pids

    except Exception as e:
        logger.error(f"Error checking running processes: {e}")
        return [], {}


async def cleanup_monitoring_processes(
    monitoring_pids: Dict[str, List[int]], completed_jobs: List[str]
) -> None:
    """Kill monitoring processes for completed jobs in batch"""
    pids_to_kill = []
    for job_id in completed_jobs:
        if job_id in monitoring_pids:
            pids_to_kill.extend(monitoring_pids[job_id])

    if pids_to_kill:
        # Batch kill - more efficient than individual kills
        try:
            # Use kill with PID list for efficiency
            pid_list = " ".join(str(pid) for pid in pids_to_kill)
            subprocess.run(f"kill -TERM {pid_list}", shell=True, timeout=5)
            logger.debug(f"Stopped {len(pids_to_kill)} monitoring processes")
        except Exception as e:
            logger.warning(f"Batch kill failed, trying individual kills: {e}")
            # Fallback to individual kills
            for pid in pids_to_kill:
                try:
                    subprocess.run(["kill", "-TERM", str(pid)], timeout=1)
                except Exception:
                    pass


async def collect_docker_stats(eval_dir: Path) -> None:
    """Collect Docker stats and append to docker_stats.json file"""
    try:
        returncode, stdout, stderr = await run_subprocess_safe(
            "docker",
            "stats",
            "--no-stream",
            "--no-trunc",
            "--format",
            "json",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            timeout=10.0,
        )

        if returncode != 0:
            logger.debug(f"docker stats failed: {stderr.decode()}")
            return

        # Parse the JSON output (each line is a separate JSON object)
        docker_stats = []
        for line in stdout.decode().strip().split("\n"):
            if line.strip():
                try:
                    import json

                    stat = json.loads(line)
                    # Add timestamp to each stat entry
                    from datetime import datetime, timezone

                    stat["timestamp"] = datetime.now(timezone.utc).isoformat()
                    docker_stats.append(stat)
                except json.JSONDecodeError:
                    continue

        if docker_stats:
            # Append to docker_stats.json file
            docker_stats_file = eval_dir / "docker_stats.json"

            # Read existing data if file exists
            existing_stats = []
            if docker_stats_file.exists():
                try:
                    with open(docker_stats_file, "r") as f:
                        existing_stats = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    existing_stats = []

            # Append new stats
            existing_stats.extend(docker_stats)

            # Write back to file
            with open(docker_stats_file, "w") as f:
                json.dump(existing_stats, f, indent=2)

            logger.debug(f"Collected {len(docker_stats)} Docker stats entries")

    except Exception as e:
        logger.debug(f"Error collecting Docker stats: {e}")


async def find_completed_jobs(running_job_ids: List[str]) -> List[str]:
    """Find which jobs are no longer running by checking processes (legacy function)"""
    completed, _ = await find_completed_jobs_and_monitors(running_job_ids)
    return completed


def cleanup_running_jobs(target_job_ids: set = None) -> int:
    """Find and terminate running CRS jobs, filtered by job IDs"""
    try:
        # Find all processes with CRS_JOB_ID using synchronous subprocess
        result = subprocess.run(
            ["ps", "axe"], capture_output=True, text=True, timeout=10
        )

        if result.returncode != 0:
            logger.warning(f"ps command failed: {result.stderr}")
            return 0

        # Find all running job processes
        job_pids = []
        job_details = []
        for line in result.stdout.split("\n"):
            if "CRS_JOB_ID=" in line:
                parts = line.strip().split()
                if parts:
                    try:
                        pid = int(parts[0])
                        # Extract job ID from environment
                        job_id_match = re.search(r"CRS_JOB_ID=([a-f0-9-]+)", line)
                        job_id = job_id_match.group(1) if job_id_match else "unknown"

                        # Only include jobs that belong to this run_eval.py instance
                        if target_job_ids is not None and job_id in target_job_ids:
                            job_pids.append(pid)
                            job_details.append((pid, job_id, line.strip()))
                            logger.info(
                                f"Found CRS process: PID {pid}, Job ID {job_id[:8]}..."
                            )
                        else:
                            logger.debug(
                                f"Skipping external CRS process: PID {pid}, Job ID"
                                f" {job_id[:8]}..."
                            )
                    except (ValueError, IndexError):
                        continue

        if not job_pids:
            logger.info("No running CRS jobs found")
            return 0

        logger.info(f"Found {len(job_pids)} running CRS processes, terminating...")
        for pid, job_id, _ in job_details:
            logger.info(f"  • PID {pid}: Job {job_id[:8]}...")

        # First try SIGTERM for graceful shutdown
        terminated_count = 0
        for pid in job_pids:
            try:
                # Send SIGTERM to the process group
                subprocess.run(
                    ["pkill", "-TERM", "-P", str(pid)], capture_output=True, timeout=5
                )
                # Also terminate the main process
                subprocess.run(
                    ["kill", "-TERM", str(pid)], capture_output=True, timeout=5
                )
                terminated_count += 1
                logger.debug(f"Sent SIGTERM to job PID {pid}")
            except Exception as e:
                logger.warning(f"Failed to terminate PID {pid}: {e}")

        # Wait for graceful shutdown
        if terminated_count > 0:
            logger.info("Waiting 10 seconds for graceful shutdown...")
            import time

            time.sleep(10)

            # Check if any processes are still running and force kill them
            remaining_pids = []
            for pid in job_pids:
                try:
                    # Check if process still exists
                    result = subprocess.run(
                        ["kill", "-0", str(pid)], capture_output=True, timeout=5
                    )
                    if result.returncode == 0:
                        remaining_pids.append(pid)
                except Exception:
                    pass  # Process no longer exists

            if remaining_pids:
                logger.warning(f"Force killing {len(remaining_pids)} remaining jobs...")
                for pid in remaining_pids:
                    try:
                        subprocess.run(
                            ["pkill", "-KILL", "-P", str(pid)],
                            capture_output=True,
                            timeout=5,
                        )
                        subprocess.run(
                            ["kill", "-KILL", str(pid)], capture_output=True, timeout=5
                        )
                        logger.debug(f"Force killed job PID {pid}")
                    except Exception as e:
                        logger.warning(f"Failed to force kill PID {pid}: {e}")

        logger.success(f"Cleanup completed: terminated {terminated_count} jobs")
        return terminated_count

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        return 0


async def cleanup_litellm_key_for_job(
    job_info: Dict, job_id: str, eval_dir: Path = None
) -> None:
    """Handle LiteLLM key cleanup and stats collection for a completed job"""
    if not job_info:
        return

    # Get the API key that was stored in the JobInfo object
    api_key = job_info.get("litellm_api_key")
    if not api_key:
        logger.debug(f"No LiteLLM API key found for job {job_id}")
        return

    try:
        # Get job details for stats storage
        target = job_info.get("target")
        hash_str = job_info.get("hash_str")

        if not target or not hash_str:
            logger.warning(
                f"Missing target or hash_str for job {job_id}, skipping stats"
                " collection"
            )
        else:
            # Use provided eval_dir or fall back to default
            if eval_dir is None:
                eval_dir = Path.cwd() / "eval_out"
                logger.debug(f"Using default eval_dir: {eval_dir}")

            # Collect key statistics before deletion
            stats = get_key_stats(api_key)
            if stats:
                # Save the statistics
                save_key_stats(eval_dir, target, hash_str, stats)
                logger.info(
                    f"Collected and saved LiteLLM stats for job {job_id} to {eval_dir}"
                )
            else:
                logger.warning(f"Failed to collect LiteLLM stats for job {job_id}")

        if job_info.get("start_other_services"):
            # Delete the API key
            if delete_key(api_key):
                logger.info(f"Successfully deleted LiteLLM key for job {job_id}")
            else:
                logger.warning(f"Failed to delete LiteLLM key for job {job_id}")

    except Exception as e:
        logger.error(f"Error during LiteLLM key cleanup for job {job_id}: {e}")


async def cleanup_job_temp_directory(job_info: Dict, job_id: str) -> bool:
    """Clean up temporary directory for a single job"""
    temp_multilang_root = job_info.get("temp_multilang_root")
    if temp_multilang_root:
        temp_dir = Path(temp_multilang_root).parent
        if temp_dir.exists() and temp_dir.name.startswith("crs-"):
            fire_and_ignore(f"sudo rm -rf {temp_dir}")
            logger.debug(f"Cleaning up temp directory for job {job_id}: {temp_dir}")
            return True
    return False


async def cleanup_temp_directories(
    job_queue: JobQueue, should_cleanup: bool = True
) -> int:
    """Clean up temporary CRS-multilang directories from all jobs"""
    if not should_cleanup:
        logger.info("Cleanup disabled, skipping temporary directory cleanup")
        return 0

    cleaned_count = 0

    # Clean up all jobs (pending, running, completed)
    all_jobs = job_queue.get_all_jobs()
    for job_info in all_jobs:
        job_id = job_info["job_id"]
        if await cleanup_job_temp_directory(job_info, job_id):
            cleaned_count += 1

    if cleaned_count > 0:
        logger.info(f"Cleaned up {cleaned_count} temporary directories")

    return cleaned_count


async def cleanup_docker_containers(job_queue: JobQueue) -> int:
    """Find and stop Docker containers related to CRS jobs from this instance only"""
    try:
        # Get temp directories from all jobs (pending, running, completed) in this instance
        temp_dirs = []
        current_job_ids = set()

        all_jobs = job_queue.get_all_jobs()
        for job_info in all_jobs:
            job_id = job_info.get("job_id")
            if job_id:
                current_job_ids.add(job_id)

            temp_multilang_root = job_info.get("temp_multilang_root")
            if temp_multilang_root:
                temp_dir = Path(temp_multilang_root).parent
                temp_dirs.append(str(temp_dir))

        if not temp_dirs:
            logger.info("No temp directories to match against")
            return 0

        logger.info(
            f"Checking {len(temp_dirs)} temp directories from this instance against"
            " Docker containers..."
        )

        # Find all running Docker containers
        returncode, stdout, stderr = await run_subprocess_safe(
            "docker",
            "ps",
            "-q",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            timeout=10.0,
        )

        if returncode != 0:
            logger.warning(f"docker ps failed: {stderr.decode()}")
            return 0

        container_ids = [
            cid.strip() for cid in stdout.decode().split("\n") if cid.strip()
        ]

        if not container_ids:
            logger.info("No running Docker containers found")
            return 0

        # Check which containers have bind mounts to our temp directories
        crs_containers = []
        for container_id in container_ids:
            # Get container bind mounts
            inspect_returncode, inspect_stdout, _ = await run_subprocess_safe(
                "docker",
                "inspect",
                container_id,
                "--format",
                "{{range .HostConfig.Binds}}{{.}} {{end}}",
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10.0,
            )

            if inspect_returncode == 0:
                binds = inspect_stdout.decode().strip()
                # Check if any bind mount matches our temp directories
                if binds:
                    for temp_dir in temp_dirs:
                        if temp_dir in binds:
                            crs_containers.append(container_id)
                            logger.debug(
                                f"Found CRS container: {container_id} (temp_dir:"
                                f" {temp_dir})"
                            )
                            break

        if not crs_containers:
            logger.info("No Docker containers using our temp directories found")
            return 0

        logger.info(
            f"Found {len(crs_containers)} containers using temp directories,"
            " stopping..."
        )

        # Stop containers
        stopped_count = 0
        for container_id in crs_containers:
            try:
                # Stop container
                fire_and_ignore(f"docker stop {container_id}")
                stopped_count += 1
                logger.debug(f"Stopped Docker container: {container_id}")
            except Exception as e:
                logger.warning(f"Failed to stop container {container_id}: {e}")

        # Force kill any remaining containers after a short wait
        if stopped_count > 0:
            await asyncio.sleep(5)

            for container_id in crs_containers:
                try:
                    # Force kill container
                    fire_and_ignore(f"docker kill {container_id}")
                    logger.debug(f"Force killed Docker container: {container_id}")
                except Exception:
                    # Container might already be stopped
                    pass

        logger.success(f"Docker cleanup completed: stopped {stopped_count} containers")
        return stopped_count

    except Exception as e:
        logger.error(f"Error during Docker cleanup: {e}")
        return 0


async def check_completed_jobs(
    cpu_manager: CPUSlotManager,
    job_queue: JobQueue,
    cleanup_event: asyncio.Event = None,
    should_cleanup: bool = True,
    eval_dir: Path = None,
    docker_stats_interval: int = 300,  # 5 minutes default
) -> None:
    """Background task to check for completed jobs every 1 minute"""
    docker_stats_counter = 0
    docker_stats_cycles = docker_stats_interval // 60  # Convert to 1-minute cycles

    while not job_queue.is_empty():
        try:
            # Check for cleanup request
            if cleanup_event and cleanup_event.is_set():
                logger.info("Cleanup requested, terminating running jobs...")
                # Only cleanup jobs that belong to this run_eval.py instance
                current_job_ids = set(job_queue.all_jobs.keys())
                cleanup_running_jobs(current_job_ids)

                # Clean up Docker containers
                await cleanup_docker_containers(job_queue)

                # Clean up LiteLLM keys and temp directories for all jobs
                running_job_ids = list(job_queue.running.keys())
                for job_id in running_job_ids:
                    job_info = job_queue.running.get(job_id)
                    if job_info:
                        # Handle LiteLLM key cleanup for interrupted jobs
                        await cleanup_litellm_key_for_job(job_info, job_id, eval_dir)

                        # Clean up temp directory if cleanup is enabled
                        if should_cleanup:
                            await cleanup_job_temp_directory(job_info, job_id)

                    await cpu_manager.release(job_id)
                    job_queue.mark_completed(job_id)

                # Clean up any remaining temp directories
                await cleanup_temp_directories(job_queue, should_cleanup)

                logger.info("Cleanup completed, exiting monitoring")
                return

            running_job_ids = list(job_queue.running.keys())
            completed, monitoring_pids = await find_completed_jobs_and_monitors(
                running_job_ids
            )

            # Collect Docker stats at specified interval
            if eval_dir and docker_stats_counter % docker_stats_cycles == 0:
                await collect_docker_stats(eval_dir)
            docker_stats_counter += 1

            # Kill mpstat processes for completed jobs
            if completed:
                await cleanup_monitoring_processes(monitoring_pids, completed)

            for job_id in completed:
                job_info = None
                target = None

                # Get job info before marking as completed
                if job_id in job_queue.running:
                    job_info = job_queue.running[job_id]
                    target = job_info.get("target")

                # Generate ZIP files for completed experiment
                if job_info and target and eval_dir:
                    config_hash = job_info.get("hash_str")
                    if config_hash:
                        try:
                            import json

                            from generate_zips import generate_experiment_zips

                            # Read config to get harnesses
                            config_file = (
                                eval_dir / "configs" / target / f"{config_hash}.json"
                            )
                            with open(config_file, "r") as f:
                                harnesses = json.load(f)["target_harnesses"]

                            # Generate ZIPs for each harness
                            for harness in harnesses:
                                success = generate_experiment_zips(
                                    eval_dir, config_hash, target, harness
                                )
                                if success:
                                    logger.info(
                                        "Generated ZIP files for"
                                        f" {config_hash[:8]}/{target}/{harness}"
                                    )
                                else:
                                    logger.warning(
                                        "Failed to generate ZIP files for"
                                        f" {config_hash[:8]}/{target}/{harness}"
                                    )
                        except Exception as e:
                            logger.warning(
                                "Failed to generate ZIP files for"
                                f" {config_hash[:8]}/{target}: {e}"
                            )

                # Handle LiteLLM key cleanup and stats collection
                await cleanup_litellm_key_for_job(job_info, job_id, eval_dir)

                # Clean up temp directory for completed job if cleanup is enabled
                if should_cleanup and job_info:
                    await cleanup_job_temp_directory(job_info, job_id)

                await cpu_manager.release(job_id)
                job_queue.mark_completed(job_id)

                # Mark target as completed to dispatch next job for that target
                if target:
                    job_queue.mark_target_completed(target)

            await asyncio.sleep(60)  # Check every 1 minute

        except Exception as e:
            logger.error(f"Error in job monitoring: {e}")
            await asyncio.sleep(60)

    logger.info("Job monitoring completed - all jobs finished")


async def dispatch_jobs(
    cpu_manager: CPUSlotManager,
    job_queue: JobQueue,
    job_executor,
    *args,
    cleanup_event=None,
) -> None:
    """Background task to start jobs when slots are available"""
    total_jobs_added = len(job_queue.all_jobs)  # Get total from all_jobs dict
    jobs_started = 0

    while True:
        try:
            # Check cleanup event first - stop dispatching if cleanup requested
            if cleanup_event and cleanup_event.is_set():
                logger.info("Cleanup requested, stopping job dispatcher")
                break

            # Get next job with timeout to allow periodic checking
            try:
                job_info = await asyncio.wait_for(job_queue.get_next_job(), timeout=1.0)
            except asyncio.TimeoutError:
                # Check if all jobs are done
                if job_queue.pending.empty() and len(job_queue.running) == 0:
                    break
                continue

            # Check target collision if prevention is enabled
            target = job_info.get("target")
            if (
                job_queue.prevent_target_collision
                and target
                and job_queue.is_target_running(target)
            ):
                # Queue this job for later when target becomes available
                await job_queue.queue_job_for_target(target, job_info)
                continue

            # Try to allocate cores for the job
            cores_needed = job_info.get("cores_needed", 1)
            allocation = await cpu_manager.allocate(job_info["job_id"], cores_needed)

            if allocation is not None:
                # Mark target as running if collision prevention is enabled
                if job_queue.prevent_target_collision and target:
                    job_queue.mark_target_running(target)

                # Start the job
                start_core, end_core = allocation
                job_info["allocation"] = allocation

                await job_executor(job_info, *args)
                job_queue.mark_running(job_info["job_id"], job_info)
                jobs_started += 1

                target_name = job_info.get("target", "unknown").replace("/", "-")
                hash_short = job_info.get("hash_str", "unknown")[:8]
                collision_status = (
                    " (target collision prevention enabled)"
                    if job_queue.prevent_target_collision
                    else ""
                )
                logger.info(
                    f"Started [{jobs_started}/{total_jobs_added}]"
                    f" {target_name}-{hash_short} (cores"
                    f" {start_core}-{end_core}){collision_status}"
                )
            else:
                # No slots available, put job back in queue
                await job_queue.add_job(job_info)
                await asyncio.sleep(2)  # Wait a bit longer before retrying

        except Exception as e:
            logger.error(f"Error in job dispatcher: {e}")
            await asyncio.sleep(1)

    logger.info(f"Job dispatching completed - all {jobs_started} jobs started")


def create_job_id() -> str:
    """Generate a unique job ID"""
    return str(uuid.uuid4())


def is_experiment_finished(eval_dir: Path, target: str, config_hash: str) -> bool:
    """Check if experiment completed successfully by examining stdout file"""
    stdout_file = eval_dir / "stdout" / target / f"{config_hash}.txt"

    # Check if stdout file exists
    if not stdout_file.exists():
        return False

    try:
        # Read only the last 10K bytes to handle large files efficiently
        with open(stdout_file, "rb") as f:
            # Get file size
            f.seek(0, 2)  # Seek to end
            file_size = f.tell()

            if file_size == 0:
                return False

            # Read last 10K bytes (or entire file if smaller)
            read_size = min(10240, file_size)  # 10K bytes
            f.seek(file_size - read_size)

            # Read and decode the tail of the file
            tail_bytes = f.read()
            tail_text = tail_bytes.decode("utf-8", errors="replace")

        # Split into lines and get the last 3 lines
        lines = tail_text.splitlines()
        if len(lines) < 3:
            return False

        last_3_lines = lines[-3:]

        # Create regex pattern that matches the completion command
        completion_pattern = re.compile(
            r"Run cp -r .*/workdir_result"
            rf" .*/results/{re.escape(config_hash)}/{re.escape(target)}"
        )

        for line in last_3_lines:
            if completion_pattern.search(line.strip()):
                return True

        return False

    except Exception as e:
        logger.debug(f"Error reading stdout file {stdout_file}: {e}")
        return False


def get_experiment_status(eval_dir: Path, target: str, config_hash: str) -> str:
    """Return experiment status: 'completed', 'incomplete', or 'not_started'"""
    stdout_file = eval_dir / "stdout" / target / f"{config_hash}.txt"
    metadata_file = eval_dir / "metadata" / target / f"{config_hash}.json"
    results_dir = eval_dir / "results" / config_hash / target

    # Check if experiment is completed
    if is_experiment_finished(eval_dir, target, config_hash):
        return "completed"

    # Check if any experiment data exists (indicating it was started but not completed)
    if stdout_file.exists() or metadata_file.exists() or results_dir.exists():
        return "incomplete"

    # No data exists - experiment not started
    return "not_started"


def cleanup_incomplete_experiment(
    eval_dir: Path, target: str, config_hash: str
) -> bool:
    """Remove data for a specific incomplete experiment (target + config_hash)"""
    # Validate inputs
    if not config_hash or len(config_hash) < 8:
        logger.error(f"Invalid config_hash: {config_hash}")
        return False

    # Double-check it's actually incomplete
    if is_experiment_finished(eval_dir, target, config_hash):
        logger.warning(
            f"Experiment {target}/{config_hash} appears complete, skipping cleanup"
        )
        return False

    removed_files = []

    try:
        # 1. Remove stdout file for this target/config
        stdout_file = eval_dir / "stdout" / target / f"{config_hash}.txt"
        if stdout_file.exists():
            stdout_file.unlink()
            removed_files.append(str(stdout_file))

        # 2. Remove metadata file for this target/config
        metadata_file = eval_dir / "metadata" / target / f"{config_hash}.json"
        if metadata_file.exists():
            metadata_file.unlink()
            removed_files.append(str(metadata_file))

        # 3. Remove ONLY this target's results directory (not entire config_hash dir)
        target_results_dir = eval_dir / "results" / config_hash / target
        if target_results_dir.exists():
            shutil.rmtree(target_results_dir)  # Only removes this specific target
            removed_files.append(str(target_results_dir))

        # 4. Keep config file (needed for re-running)
        # configs/{target}/{config_hash}.json - PRESERVED

        if removed_files:
            logger.info(f"Cleaned up incomplete experiment {target}/{config_hash[:8]}:")
            for file_path in removed_files:
                logger.info(f"  • Removed: {file_path}")

        return len(removed_files) > 0

    except Exception as e:
        logger.error(f"Error cleaning up experiment {target}/{config_hash}: {e}")
        return False


def analyze_experiments_status(eval_dir: Path, experiment_info: Dict) -> Dict:
    """Analyze all planned experiments and categorize them by status"""
    status_summary = {"completed": [], "incomplete": [], "not_started": []}

    for target, experiment_configs in experiment_info.items():
        for hash_str, config_file in experiment_configs:
            status = get_experiment_status(eval_dir, target, hash_str)
            status_summary[status].append((target, hash_str, config_file))

    return status_summary
