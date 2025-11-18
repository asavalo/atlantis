#!/usr/bin/env python3
"""
End-to-end test script for CRS-SARIF.

This script:
1. Parses the target YAML file containing project configurations
2. For each project, runs crs_test.py to build and run CRS
3. Sends SARIF files to CRS using test_crs_sarif.py
4. Collects and reports test results
"""

import argparse
import csv
import json
import logging
import os
import random
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

import coloredlogs
import docker
import psutil
import yaml

# Configure logging
logger = logging.getLogger(__name__)
coloredlogs.install(fmt="%(asctime)s %(levelname)s %(message)s")


# --- Logging setup ---
class TeeStdout:
    def __init__(self, log_path):
        self.terminal = sys.stdout
        self.log = open(log_path, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()


class TeeStderr:
    def __init__(self, log_path):
        self.terminal = sys.stderr
        self.log = open(log_path, "a", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()


def setup_global_tee(log_dir: Path):
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = log_dir / f"e2e_test-{ts}.log"
    sys.stdout = TeeStdout(log_path)
    sys.stderr = TeeStderr(log_path)
    print(f"[E2E-TEST] Logging to {log_path}")
    return log_path


# --- Logging functions ---
def log(message: str):
    print(f"[E2E-TEST] {message}")


def warn(message: str):
    print(f"[E2E-TEST][WARN] {message}")


def error(message: str):
    print(f"[E2E-TEST][ERROR] {message}")


def find_free_port(start_port: int = 4321, used_ports: Set[int] = None) -> int:
    """Find a free port using random selection from multiple ranges."""
    if used_ports is None:
        used_ports = set()

    # Define multiple port ranges to choose from randomly
    port_ranges = [
        (5000, 5999),  # 5000-5999
        (6000, 6999),  # 6000-6999
        (7000, 7999),  # 7000-7999
        (8000, 8999),  # 8000-8999
        (9000, 9999),  # 9000-9999
        (10000, 10999),  # 10000-10999
        (12000, 12999),  # 12000-12999
        (15000, 15999),  # 15000-15999
    ]

    attempts = 0
    max_attempts = 100  # Safety limit to prevent infinite loops

    while attempts < max_attempts:
        # Randomly select a port range
        range_start, range_end = random.choice(port_ranges)

        # Randomly select a port within that range
        port = random.randint(range_start, range_end)

        # Skip if already in used ports
        if port in used_ports:
            attempts += 1
            continue

        # Check if port is actually free
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
                s.listen(1)
        except OSError:
            attempts += 1
            continue

        # Check if port is used by any docker container
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Ports}}"],
                capture_output=True,
                text=True,
                check=True,
            )
            # Check if any container is using this port
            if f":{port}->" in result.stdout or f":{port}/" in result.stdout:
                attempts += 1
                continue
        except subprocess.CalledProcessError:
            warn("Failed to check docker container ports, continuing anyway")

        # Port is free
        used_ports.add(port)
        log(f"Selected random port {port} from range {range_start}-{range_end}")
        return port

    # Fallback to sequential search if random selection fails
    warn(
        f"Random port selection failed after {max_attempts} attempts, falling back to sequential search from {start_port}"
    )
    port = start_port
    while port in used_ports:
        port += 1

    # Check if port is actually free
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
                s.listen(1)
        except OSError:
            port += 1
            if port > start_port + 1000:  # Safety limit
                raise RuntimeError(
                    f"Could not find free port starting from {start_port}"
                )
            continue

        # Then check if port is used by any docker container
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Ports}}"],
                capture_output=True,
                text=True,
                check=True,
            )
            # Check if any container is using this port
            if f":{port}->" in result.stdout or f":{port}/" in result.stdout:
                port += 1
                continue
        except subprocess.CalledProcessError:
            warn("Failed to check docker container ports, continuing anyway")

        # Port is free
        used_ports.add(port)
        return port


class PortManager:
    """Manages port allocation for multiple projects."""

    def __init__(self, start_port: int = 4321):
        self.start_port = start_port
        self.used_ports: Set[int] = set()
        self.project_ports: Dict[str, int] = {}

    def allocate_port(self, project_name: str) -> int:
        """Allocate a port for a project."""
        if project_name in self.project_ports:
            return self.project_ports[project_name]

        # Clean up any stale ports first
        self._cleanup_stale_ports()

        port = find_free_port(self.start_port, self.used_ports)
        self.project_ports[project_name] = port
        log(f"Allocated port {port} for project {project_name}")
        return port

    def get_port(self, project_name: str) -> int:
        """Get the allocated port for a project."""
        return self.project_ports.get(project_name, self.start_port)

    def release_port(self, project_name: str):
        """Release the port allocated to a project."""
        if project_name in self.project_ports:
            port = self.project_ports.pop(project_name)
            self.used_ports.discard(port)
            log(f"Released port {port} for project {project_name}")

    def _cleanup_stale_ports(self):
        """Clean up ports that are no longer in use by Docker containers."""
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Ports}}"],
                capture_output=True,
                text=True,
                check=True,
            )
            used_ports = set()
            for line in result.stdout.splitlines():
                # Extract port numbers from docker ps output
                if "->" in line:
                    port = line.split("->")[0].split(":")[-1]
                    try:
                        used_ports.add(int(port))
                    except ValueError:
                        continue

            # Remove ports that are no longer in use
            self.used_ports = self.used_ports.intersection(used_ports)
        except subprocess.CalledProcessError:
            warn("Failed to cleanup stale ports")


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 3600,
    log_file: Optional[Path] = None,
) -> bool:
    """Run a command and return True if successful. Print output in real time."""
    cmd_str = " ".join(map(str, cmd))
    log(f"Running: {cmd_str}")
    if cwd:
        log(f"Working directory: {cwd}")

    # Create log file if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log(f"Saving command output to: {log_file}")

    try:
        with subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        ) as process:
            # Read output in real-time
            for line in process.stdout:
                line = line.strip()
                log(line)
                if log_file:
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"{line}\n")

            # Wait for process to complete
            return_code = process.wait(timeout=timeout)

            if return_code == 0:
                log(f"Command succeeded: {cmd_str}")
                return True
            else:
                error(f"Command failed with return code {return_code}: {cmd_str}")
                return False

    except subprocess.TimeoutExpired:
        error(f"Command timed out after {timeout} seconds: {cmd_str}")
        return False
    except Exception as e:
        error(f"Unexpected error running command: {e}")
        return False


def wait_for_crs_ready(
    host: str = "http://localhost:4321", timeout: int = 300, project_name: str = None
) -> bool:
    """Wait for CRS to be ready to accept requests."""
    import requests

    log(f"Waiting for CRS to be ready at {host}")
    start_time = time.time()
    container_restart_attempted = False

    # Extract port from host for container restart
    crs_port = None
    if ":" in host:
        try:
            crs_port = int(host.split(":")[-1])
        except ValueError:
            pass

    while time.time() - start_time < timeout:
        try:
            # Try a GET request to the root path.
            # Any response (even an error like 404) indicates the server is up.
            requests.get(f"{host}/", timeout=5)
            log("CRS HTTP server is responding!")
            return True
        except requests.RequestException as e:
            # This includes ConnectionError, Timeout, etc.
            elapsed_time = int(time.time() - start_time)
            log(f"CRS not yet ready (request failed: {e}) - {elapsed_time}s elapsed")

            # If we have project name and enough time has passed, try container restart
            if (
                project_name
                and not container_restart_attempted
                and elapsed_time > 120
                and crs_port
            ):  # Wait at least 2 minutes before restart

                log(
                    f"CRS not responding after {elapsed_time}s, checking container status..."
                )
                if check_and_restart_container(project_name, crs_port):
                    log(
                        "Container restart attempted, waiting for CRS to come back up..."
                    )
                    container_restart_attempted = True
                    time.sleep(30)  # Give extra time after restart
                    continue
                else:
                    warn(f"Failed to restart container for project: {project_name}")

        time.sleep(30)

    error(f"CRS did not become ready within {timeout} seconds")
    return False


def cleanup_old_analysis_files(output_dir: Path, project_name: str):
    """
    Clean up old analysis files for a project.

    Args:
        output_dir (Path): Directory containing analysis files
        project_name (str): Name of the project
    """
    try:
        # Find all analysis files for this project
        old_files = list(output_dir.glob(f"*_{project_name}_*.json"))
        for file in old_files:
            file.unlink()
            log(f"Removed old analysis file: {file}")
    except Exception as e:
        warn(f"Failed to cleanup old analysis files: {e}")


def wait_for_sarif_analysis(
    project_name: str, output_dir: Path, timeout: int = 300
) -> bool:
    """
    Wait for SARIF analysis results to be generated.

    Args:
        project_name (str): Name of the project
        output_dir (Path): Directory where analysis results should be saved
        timeout (int): Maximum time to wait in seconds

    Returns:
        bool: True if analysis results were found, False otherwise
    """
    log(f"Waiting for SARIF analysis results for project: {project_name}")

    # Clean up old analysis files before starting

    # Record start time for checking new files
    start_time = time.time()
    start_timestamp = time.strftime("%Y%m%d_%H%M%S", time.localtime(start_time))

    while time.time() - start_time < timeout:
        # Check for new analysis files (only those created after we started)
        analysis_files = []
        for file in output_dir.glob(f"*_{project_name}_*.json"):
            try:
                # Extract timestamp from filename
                file_timestamp = file.stem.split("_")[-1]
                if file_timestamp > start_timestamp:
                    analysis_files.append(file)
            except Exception:
                continue

        if analysis_files:
            log(
                f"Found {len(analysis_files)} new analysis files for project: {project_name}"
            )
            # Print the actual files found
            for file in analysis_files:
                log(f"  - {file.name}")
            return True

        time.sleep(10)
        log(
            f"Still waiting for analysis results... ({int(time.time() - start_time)}s elapsed)"
        )

    error(f"Timeout waiting for SARIF analysis results for project: {project_name}")
    return False


def cleanup_docker_resources(project_name: str) -> None:
    """Clean up Docker resources for a project."""
    log(f"Cleaning up Docker resources for project: {project_name}")

    # Stop background CRS process if it exists
    pid_file = Path(f"/tmp/crs_process_{project_name}.pid")
    if pid_file.exists():
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())

            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                log(f"Terminating CRS process with PID: {pid}")
                process.terminate()
                try:
                    process.wait(timeout=10)
                except psutil.TimeoutExpired:
                    log(f"Force killing CRS process with PID: {pid}")
                    process.kill()

            pid_file.unlink()
            log(f"Cleaned up CRS process and PID file for project: {project_name}")
        except Exception as e:
            warn(f"Failed to cleanup CRS process: {e}")

    # Force remove containers that might be in conflict state
    container_names = [
        f"crs-sarif-{project_name}",
        f"crs-redis-{project_name}",
        f"sarif-tracer-{project_name}",
    ]

    for container_name in container_names:
        try:
            # Try to force remove the container
            result = subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                log(f"Successfully removed container: {container_name}")
            else:
                # Container might not exist, which is fine
                if "No such container" not in result.stderr:
                    warn(
                        f"Failed to remove container {container_name}: {result.stderr}"
                    )
        except subprocess.TimeoutExpired:
            warn(f"Timeout while removing container: {container_name}")
        except Exception as e:
            warn(f"Error removing container {container_name}: {e}")

    # Stop and remove containers using docker-compose
    compose_project_name = f"crs-sarif-{project_name}"
    try:
        # First try graceful shutdown
        result = subprocess.run(
            [
                "docker",
                "compose",
                "--project-name",
                compose_project_name,
                "down",
                "-v",
                "--timeout",
                "30",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            log(
                f"Successfully stopped docker-compose services for project: {project_name}"
            )
        else:
            warn(f"Docker-compose down failed: {result.stderr}")

        # If graceful shutdown failed, try force removal
        if result.returncode != 0:
            log(f"Attempting force removal for project: {project_name}")
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "--project-name",
                    compose_project_name,
                    "down",
                    "-v",
                    "--remove-orphans",
                    "--timeout",
                    "10",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

    except subprocess.TimeoutExpired:
        warn(f"Timeout during docker-compose cleanup for project: {project_name}")
    except Exception as e:
        warn(f"Error during docker-compose cleanup: {e}")

    # Remove network if it exists
    network_name = f"crs-sarif-{project_name}_crs-network"
    try:
        result = subprocess.run(
            ["docker", "network", "rm", network_name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            log(f"Successfully removed network: {network_name}")
        elif "No such network" not in result.stderr:
            warn(f"Failed to remove network {network_name}: {result.stderr}")
    except subprocess.TimeoutExpired:
        warn(f"Timeout while removing network: {network_name}")
    except Exception as e:
        warn(f"Error removing network {network_name}: {e}")

    # Additional cleanup: remove any dangling containers/networks related to the project
    try:
        # Find and remove any containers with the project name
        result = subprocess.run(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"name={project_name}",
                "--format",
                "{{.Names}}",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            container_names = result.stdout.strip().split("\n")
            for container_name in container_names:
                if container_name.strip():
                    subprocess.run(
                        ["docker", "rm", "-f", container_name.strip()],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    log(f"Cleaned up dangling container: {container_name.strip()}")
    except Exception as e:
        warn(f"Error during additional container cleanup: {e}")

    log(f"Docker cleanup completed for project: {project_name}")


def check_and_restart_container(project_name: str, crs_port: int) -> bool:
    """
    Check if CRS container is running and restart if necessary.

    Args:
        project_name (str): Name of the project
        crs_port (int): Port number for CRS

    Returns:
        bool: True if container is running or successfully restarted, False otherwise
    """
    try:
        client = docker.from_env()
        container_name = f"crs-sarif-{project_name}"

        try:
            container = client.containers.get(container_name)

            if container.status == "running":
                log(f"Container {container_name} is running")
                return True
            elif container.status in ["paused", "exited"]:
                log(
                    f"Container {container_name} is {container.status}. Attempting to restart..."
                )
                try:
                    container.restart()
                    time.sleep(15)  # Wait for container to start
                    container.reload()
                    if container.status == "running":
                        log(f"Successfully restarted container {container_name}")
                        return True
                    else:
                        warn(
                            f"Failed to restart container {container_name}, status: {container.status}"
                        )
                        return False
                except Exception as e:
                    warn(f"Failed to restart container {container_name}: {e}")
                    return False
            else:
                warn(
                    f"Container {container_name} has unexpected status: {container.status}"
                )
                return False

        except docker.errors.NotFound:
            warn(f"Container {container_name} not found")
            return False

    except Exception as e:
        warn(f"Error checking container status for project {project_name}: {e}")
        return False


def run_command_background(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 3600,
    project_name: str = None,
) -> subprocess.Popen:
    """Run a command in background and return the process object."""
    cmd_str = " ".join(map(str, cmd))
    log(f"Running in background: {cmd_str}")
    if cwd:
        log(f"Working directory: {cwd}")

    try:
        process = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )

        log(f"Background process started with PID: {process.pid}")

        # Store process info for cleanup
        if project_name:
            pid_file = Path(f"/tmp/crs_process_{project_name}.pid")
            with open(pid_file, "w") as f:
                f.write(str(process.pid))
            log(f"PID saved to: {pid_file}")

        # Start a background thread to read and log output
        def log_output():
            try:
                for line in process.stdout:
                    log(f"[CRS-{project_name}] {line.strip()}")
            except Exception as e:
                error(f"Error reading CRS output: {e}")

        log_thread = threading.Thread(target=log_output, daemon=True)
        log_thread.start()

        return process

    except Exception as e:
        error(f"Failed to start background command: {e}")
        raise


def run_crs_test(project: Dict, args: argparse.Namespace, crs_port: int) -> bool:
    """Run crs_test.py for a single project."""
    project_name = project["name"]
    project_language = project["language"]
    mode = project["mode"]

    log(f"Starting CRS test for project: {project_name} on port {crs_port}")

    # Clean up any existing Docker resources before starting
    cleanup_docker_resources(project_name)

    # Create output directory for analysis results
    output_dir = Path(args.log_dir) / project_name / "sarif_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build crs_test.py command
    cmd = [
        sys.executable,
        "crs_test.py",
        "--project-name",
        project_name,
        "--project-language",
        project_language,
        "--original-oss-fuzz-dir",
        args.original_oss_fuzz_dir,
        "--crs-test-dir",
        args.crs_test_dir,
        "--tarball-dir",
        args.tarball_dir,
        "--crs-port",
        str(crs_port),
    ]

    # Add optional arguments
    if args.multilang_dir:
        cmd.extend(["--multilang-dir", args.multilang_dir])

    if mode == "diff":
        cmd.append("--diff-mode")

    if args.not_benchmark:
        cmd.append("--not-benchmark")

    # Add build and run flags (but not --run-crs yet)
    if args.run_docker_build:
        cmd.append("--run-docker-build")
    if args.run_sarif_build:
        cmd.append("--run-sarif-build")
    if args.run_function_tracer:
        cmd.append("--run-function-tracer")

    # Run everything except CRS first
    success = run_command(
        cmd,
        timeout=args.build_timeout,
        log_file=output_dir / f"{project_name}_build.log",
    )  # Use args.build_timeout

    if not success:
        error(f"CRS test failed for project: {project_name}")
        cleanup_docker_resources(project_name)
        return False

    log(f"CRS test (build phase) completed successfully for project: {project_name}")

    # If CRS should be started, run it in background
    if args.run_crs:
        log(f"Starting CRS in background for project: {project_name}")

        # Create CRS command
        crs_cmd = [
            sys.executable,
            "crs_test.py",
            "--project-name",
            project_name,
            "--project-language",
            project_language,
            "--original-oss-fuzz-dir",
            args.original_oss_fuzz_dir,
            "--crs-test-dir",
            args.crs_test_dir,
            "--tarball-dir",
            args.tarball_dir,
            "--crs-port",
            str(crs_port),
            "--run-crs",  # Only run CRS
        ]

        # Add optional arguments
        if args.multilang_dir:
            crs_cmd.extend(["--multilang-dir", args.multilang_dir])
        if mode == "diff":
            crs_cmd.append("--diff-mode")
        if args.not_benchmark:
            crs_cmd.append("--not-benchmark")

        # Start CRS in background
        crs_process = run_command_background(crs_cmd, project_name=project_name)

        # Wait for CRS to be ready
        crs_host = f"http://localhost:{crs_port}"
        if not wait_for_crs_ready(
            crs_host, timeout=args.crs_ready_timeout, project_name=project_name
        ):
            error(f"CRS not ready for project: {project_name}")
            cleanup_docker_resources(project_name)
            return False

        # Send SARIF files if specified
        if args.send_sarif_files:
            if not send_sarif_files(project, args, crs_port):
                error(f"Failed to send SARIF files for project: {project_name}")
                cleanup_docker_resources(project_name)
                return False

            # # Wait for analysis results
            # if not wait_for_sarif_analysis(project_name, output_dir):
            #     error(f"Failed to get analysis results for project: {project_name}")
            #     cleanup_docker_resources(project_name)
            #     return False

            log(f"Successfully completed SARIF analysis for project: {project_name}")
        else:
            log(f"Waiting 10 minute for project: {project_name}")
            time.sleep(args.extra_wait if args.extra_wait else 600)
            log(f"Successfully completed CRS setup for project: {project_name}")

    return True


def send_sarif_files(project: Dict, args: argparse.Namespace, crs_port: int) -> bool:
    """Send SARIF files for a project to CRS."""
    project_name = project["name"]
    sarif_paths = project.get("sarif_paths", [])

    if not sarif_paths:
        warn(f"No SARIF paths specified for project: {project_name}")
        return True

    log(f"Sending {len(sarif_paths)} SARIF files for project: {project_name}")

    success = True
    crs_host = f"http://localhost:{crs_port}"

    # Create project-specific output directory
    output_dir = Path(args.log_dir) / project_name / "sarif_results"
    output_dir.mkdir(parents=True, exist_ok=True)

    cleanup_old_analysis_files(output_dir, project_name)

    for sarif_path in sarif_paths:
        sarif_file = Path(sarif_path)

        if not sarif_file.exists():
            error(f"SARIF file not found: {sarif_file}")
            success = False
            continue

        log(f"Sending SARIF file: {sarif_file}")

        cmd = [
            sys.executable,
            "test_crs_sarif.py",
            "--sarif",
            str(sarif_file),
            "--host",
            crs_host,
            "--project-name",
            project_name,
            "--output-dir",
            str(output_dir),
            "--extra-wait",
            str(args.extra_wait),
        ]

        if not run_command(
            cmd,
            timeout=args.sarif_send_timeout,
            log_file=output_dir / f"{project_name}_send_sarif.log",
        ):  # Use args.sarif_send_timeout
            error(f"Failed to send SARIF file: {sarif_file}")
            success = False
        else:
            log(f"Successfully sent SARIF file: {sarif_file}")

    return success


def cleanup_project(project_name: str, args: argparse.Namespace) -> bool:
    """Clean up Docker containers and resources for a project."""
    log(f"Cleaning up project: {project_name}")

    success = True

    # First, clean up background CRS process and Docker resources
    try:
        cleanup_docker_resources(project_name)
    except Exception as e:
        warn(f"Failed to cleanup Docker resources for project {project_name}: {e}")
        success = False

    # Remove tracer container if it exists
    tracer_container = f"sarif-tracer-{project_name}"
    cmd = ["docker", "rm", "-f", tracer_container]
    try:
        subprocess.run(cmd, check=False, capture_output=True, text=True)
    except Exception:
        pass  # Container might not exist

    return success


def save_crs_logs(project_name: str, crs_port: int, log_dir: Path) -> bool:
    """Save CRS container logs to a specific file."""
    container_name = f"crs-sarif-{project_name}"
    log_file = log_dir / f"crs-{project_name}-port-{crs_port}.log"

    log(f"Saving CRS logs for {project_name} to {log_file}")

    try:
        # Create log directory if it doesn't exist
        log_dir.mkdir(parents=True, exist_ok=True)

        # Get container logs
        cmd = ["docker", "logs", container_name]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        # Write logs to file
        with open(log_file, "w", encoding="utf-8") as f:
            f.write(f"=== CRS Logs for {project_name} (Port: {crs_port}) ===\n")
            f.write(f"Container: {container_name}\n")
            f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            f.write("STDOUT:\n")
            f.write(result.stdout)
            f.write("\n\nSTDERR:\n")
            f.write(result.stderr)

        log(f"CRS logs saved successfully: {log_file}")
        return True

    except subprocess.TimeoutExpired:
        error(f"Timeout while getting logs for container: {container_name}")
        return False
    except Exception as e:
        error(f"Failed to save CRS logs for {project_name}: {e}")
        return False


def check_build_artifacts(project_name: str, crs_test_dir: str) -> Dict[str, bool]:
    """Check if build artifacts and status files exist for a project."""
    log(f"Checking build artifacts for project: {project_name}")

    # Expected artifacts and status files
    artifacts_to_check = [
        "codeql.tar.gz",
        "joern.tar.gz",
        "SVF.tar.gz",
        "debug.tar.gz",
        "cpg_src.tar.gz",
        "out.tar.gz",
    ]

    status_files_to_check = ["CODEQL_DONE", "ESSENTIAL_DONE", "AUX_DONE", "DONE"]

    # Build directory path
    build_dir = Path(crs_test_dir) / project_name / "shared_dir" / "build"

    results = {}

    # Check artifacts
    for artifact in artifacts_to_check:
        artifact_path = build_dir / artifact
        exists = artifact_path.exists()
        results[artifact] = exists
        if exists:
            size = artifact_path.stat().st_size
            log(f"  ✓ {artifact}: {size} bytes")
        else:
            log(f"  ✗ {artifact}: NOT FOUND")

    # Check status files
    for status_file in status_files_to_check:
        status_path = build_dir / status_file
        exists = status_path.exists()
        results[status_file] = exists
        if exists:
            log(f"  ✓ {status_file}: EXISTS")
        else:
            log(f"  ✗ {status_file}: NOT FOUND")

    log(f"Build artifacts check completed for project: {project_name}")
    return results


def save_results_to_csv(results: List[Dict], csv_path: Path):
    """Save test results including build artifacts check to CSV."""
    log(f"Saving results to CSV: {csv_path}")

    # CSV headers
    headers = [
        "project_name",
        "overall_success",
        "crs_test_success",
        "sarif_send_success",
        "cleanup_success",
        "port",
        "codeql.tar.gz",
        "CODEQL_DONE",
        "joern.tar.gz",
        "ESSENTIAL_DONE",
        "AUX_DONE",
        "SVF.tar.gz",
        "debug.tar.gz",
        "cpg_src.tar.gz",
        "out.tar.gz",
        "DONE",
    ]

    try:
        csv_path.parent.mkdir(parents=True, exist_ok=True)

        with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()

            for result in results:
                # Base result data
                row = {
                    "project_name": result.get("project", ""),
                    "overall_success": result.get("overall_success", False),
                    "crs_test_success": result.get("crs_test_success", False),
                    "sarif_send_success": result.get("sarif_send_success", False),
                    "cleanup_success": result.get("cleanup_success", False),
                    "port": result.get("port", ""),
                }

                # Add build artifacts data
                artifacts = result.get("build_artifacts", {})
                for header in headers[
                    6:
                ]:  # Skip the first 6 columns which are not artifacts
                    row[header] = artifacts.get(header, False)

                writer.writerow(row)

        log(f"Results saved to CSV successfully: {csv_path}")

        # Also print a summary table
        print_csv_summary(csv_path)

    except Exception as e:
        error(f"Failed to save results to CSV: {e}")


def print_csv_summary(csv_path: Path):
    """Print a summary of the CSV results."""
    try:
        with open(csv_path, "r", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)

            log("=" * 120)
            log("BUILD ARTIFACTS SUMMARY")
            log("=" * 120)

            # Print header
            print(
                f"{'Project':<20} {'Overall':<8} {'CodeQL':<8} {'CodeQL_D':<9} {'Joern':<8} {'Ess_D':<7} {'Aux_D':<7} {'SVF':<5} {'Debug':<7} {'CPG':<5} {'Out':<5} {'DONE':<6}"
            )
            print("-" * 120)

            for row in reader:
                project = row["project_name"][:19]  # Truncate long names
                overall = "✓" if row["overall_success"] == "True" else "✗"
                codeql_tar = "✓" if row["codeql.tar.gz"] == "True" else "✗"
                codeql_done = "✓" if row["CODEQL_DONE"] == "True" else "✗"
                joern_tar = "✓" if row["joern.tar.gz"] == "True" else "✗"
                essential_done = "✓" if row["ESSENTIAL_DONE"] == "True" else "✗"
                aux_done = "✓" if row["AUX_DONE"] == "True" else "✗"
                svf_tar = "✓" if row["SVF.tar.gz"] == "True" else "✗"
                debug_tar = "✓" if row["debug.tar.gz"] == "True" else "✗"
                cpg_tar = "✓" if row["cpg_src.tar.gz"] == "True" else "✗"
                out_tar = "✓" if row["out.tar.gz"] == "True" else "✗"
                done = "✓" if row["DONE"] == "True" else "✗"

                print(
                    f"{project:<20} {overall:<8} {codeql_tar:<8} {codeql_done:<9} {joern_tar:<8} {essential_done:<7} {aux_done:<7} {svf_tar:<5} {debug_tar:<7} {cpg_tar:<5} {out_tar:<5} {done:<6}"
                )

            log("=" * 120)

    except Exception as e:
        error(f"Failed to print CSV summary: {e}")


def process_project(
    project: Dict, args: argparse.Namespace, port_manager: PortManager
) -> Dict:
    """Process a single project: run CRS test, send SARIF files, and cleanup."""
    project_name = project["name"]
    result = {
        "project": project_name,
        "crs_test_success": False,
        "sarif_send_success": False,
        "cleanup_success": False,
        "overall_success": False,
        "port": None,
        "log_saved": False,
        "build_artifacts": {},
    }

    try:
        log(f"Processing project: {project_name}")

        # Allocate port for this project
        crs_port = port_manager.allocate_port(project_name)
        result["port"] = crs_port

        # Step 1: Run CRS test (includes CRS execution, SARIF sending, and cleanup)
        if args.run_crs_test:
            result["crs_test_success"] = run_crs_test(project, args, crs_port)
            if not result["crs_test_success"] and not args.continue_on_failure:
                return result

            # If CRS test was successful and included SARIF sending, mark it as success
            if result["crs_test_success"] and args.run_crs and args.send_sarif_files:
                result["sarif_send_success"] = True
            else:
                result["sarif_send_success"] = True  # Skip if not requested
        else:
            result["crs_test_success"] = True  # Skip if not requested
            result["sarif_send_success"] = True  # Skip if not requested

        # Step 1.5: Check build artifacts after CRS test
        if args.check_artifacts and result["crs_test_success"]:
            result["build_artifacts"] = check_build_artifacts(
                project_name, args.crs_test_dir
            )

        # Step 2: Save CRS logs before final cleanup (if CRS was not cleaned up yet)
        if args.save_logs and args.run_crs and result["crs_test_success"]:
            log_dir = Path(args.log_dir) if args.log_dir else Path("./logs")
            result["log_saved"] = save_crs_logs(project_name, crs_port, log_dir)

        # Step 3: Final cleanup (always attempt)
        if args.cleanup:
            result["cleanup_success"] = cleanup_project(project_name, args)
        else:
            result["cleanup_success"] = True  # Skip if not requested

        # Release port after cleanup
        port_manager.release_port(project_name)

        result["overall_success"] = (
            result["crs_test_success"]
            and result["sarif_send_success"]
            and result["cleanup_success"]
        )

        if result["overall_success"]:
            log(f"Successfully processed project: {project_name}")
        else:
            error(f"Failed to process project: {project_name}")

    except Exception as e:
        error(f"Unexpected error processing project {project_name}: {e}")
        result["error"] = str(e)
        # Release port on error
        port_manager.release_port(project_name)

    return result


def parse_target_yaml(yaml_path: Path) -> List[Dict]:
    """Parse the target YAML file and return list of projects."""
    try:
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        projects = data.get("projects", [])
        log(f"Loaded {len(projects)} projects from {yaml_path}")

        return projects
    except Exception as e:
        error(f"Failed to parse YAML file {yaml_path}: {e}")
        return []


def print_summary(results: List[Dict]):
    """Print a summary of test results."""
    log("=" * 80)
    log("TEST SUMMARY")
    log("=" * 80)

    total = len(results)
    successful = sum(1 for r in results if r["overall_success"])
    failed = total - successful

    log(f"Total projects: {total}")
    log(f"Successful: {successful}")
    log(f"Failed: {failed}")

    if failed > 0:
        log("\nFailed projects:")
        for result in results:
            if not result["overall_success"]:
                project = result["project"]
                port = result.get("port", "N/A")
                crs = "✓" if result["crs_test_success"] else "✗"
                sarif = "✓" if result["sarif_send_success"] else "✗"
                cleanup = "✓" if result["cleanup_success"] else "✗"
                log_saved = "✓" if result.get("log_saved", False) else "✗"

                # Add build artifacts summary if available
                artifacts = result.get("build_artifacts", {})
                if artifacts:
                    codeql_ok = "✓" if artifacts.get("codeql.tar.gz", False) else "✗"
                    joern_ok = "✓" if artifacts.get("joern.tar.gz", False) else "✗"
                    svf_ok = "✓" if artifacts.get("SVF.tar.gz", False) else "✗"
                    done_ok = "✓" if artifacts.get("DONE", False) else "✗"
                    artifacts_summary = f" ARTIFACTS=[CodeQL={codeql_ok}, Joern={joern_ok}, SVF={svf_ok}, DONE={done_ok}]"
                else:
                    artifacts_summary = ""

                log(
                    f"  {project} (port {port}): CRS={crs} SARIF={sarif} CLEANUP={cleanup} LOG={log_saved}{artifacts_summary}"
                )

    if successful > 0:
        log("\nSuccessful projects:")
        for result in results:
            if result["overall_success"]:
                project = result["project"]
                port = result.get("port", "N/A")
                log_saved = "✓" if result.get("log_saved", False) else "✗"

                # Add build artifacts summary if available
                artifacts = result.get("build_artifacts", {})
                if artifacts:
                    codeql_ok = "✓" if artifacts.get("codeql.tar.gz", False) else "✗"
                    joern_ok = "✓" if artifacts.get("joern.tar.gz", False) else "✗"
                    svf_ok = "✓" if artifacts.get("SVF.tar.gz", False) else "✗"
                    done_ok = "✓" if artifacts.get("DONE", False) else "✗"
                    artifacts_summary = f" ARTIFACTS=[CodeQL={codeql_ok}, Joern={joern_ok}, SVF={svf_ok}, DONE={done_ok}]"
                else:
                    artifacts_summary = ""

                log(
                    f"  {project} (port {port}): All steps completed successfully, LOG={log_saved}{artifacts_summary}"
                )

    log("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="End-to-end test for CRS-SARIF")

    # Required arguments
    parser.add_argument(
        "--target-yaml", type=str, required=True, help="Path to target YAML file"
    )
    parser.add_argument(
        "--original-oss-fuzz-dir",
        type=str,
        required=True,
        help="Path to original OSS-Fuzz directory",
    )
    parser.add_argument(
        "--crs-test-dir", type=str, required=True, help="Path to CRS test directory"
    )
    parser.add_argument(
        "--tarball-dir", type=str, required=True, help="Path to tarball directory"
    )

    # Optional arguments
    parser.add_argument("--multilang-dir", type=str, help="Path to multilang directory")
    parser.add_argument(
        "--start-port",
        type=int,
        default=4321,
        help="Starting port for CRS services (default: 4321)",
    )
    parser.add_argument(
        "--max-workers", type=int, default=1, help="Maximum number of parallel workers"
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="./logs",
        help="Directory to save CRS container logs and e2e logs (default: ./logs)",
    )

    # Action flags
    parser.add_argument(
        "--run-docker-build", action="store_true", help="Run docker build"
    )
    parser.add_argument(
        "--run-sarif-build", action="store_true", help="Run SARIF build"
    )
    parser.add_argument(
        "--run-function-tracer", action="store_true", help="Run function tracer"
    )
    parser.add_argument("--run-crs", action="store_true", help="Run CRS")
    parser.add_argument(
        "--run-crs-test",
        action="store_true",
        default=True,
        help="Run CRS test (default: True)",
    )
    parser.add_argument(
        "--send-sarif-files",
        action="store_true",
        default=True,
        help="Send SARIF files (default: True)",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        default=True,
        help="Cleanup after each project (default: True)",
    )
    parser.add_argument(
        "--save-logs",
        action="store_true",
        default=True,
        help="Save CRS container logs (default: True)",
    )
    parser.add_argument(
        "--check-artifacts",
        action="store_true",
        default=True,
        help="Check build artifacts and status files (default: True)",
    )

    # Control flags
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Continue processing other projects if one fails",
    )
    parser.add_argument(
        "--filter-projects",
        type=str,
        help="Comma-separated list of project names to process",
    )
    parser.add_argument(
        "--extra-wait",
        type=int,
        default=0,
        help="Extra wait time in seconds",
    )
    parser.add_argument(
        "--not-benchmark",
        action="store_true",
        help="Use non-benchmark mode (passed to crs_test.py)",
    )

    # Timeout settings
    parser.add_argument(
        "--build-timeout",
        type=int,
        default=60 * 20,
        help="Timeout for build operations in seconds (default: 1200 - 20 minutes)",
    )
    parser.add_argument(
        "--crs-ready-timeout",
        type=int,
        default=60 * 5,
        help="Timeout for waiting CRS to be ready in seconds (default: 300 - 5 minutes)",
    )
    parser.add_argument(
        "--sarif-send-timeout",
        type=int,
        default=60 * 10,
        help="Timeout for sending SARIF files in seconds (default: 600 - 10 minutes)",
    )
    parser.add_argument(
        "--sarif-analysis-timeout",
        type=int,
        default=60 * 5,
        help="Timeout for waiting SARIF analysis results in seconds (default: 300 - 5 minutes)",
    )
    parser.add_argument(
        "--command-timeout",
        type=int,
        default=60 * 60,
        help="Default timeout for general commands in seconds (default: 3600 - 1 hour)",
    )

    args = parser.parse_args()

    # Setup global logging
    log_dir = Path(args.log_dir) if args.log_dir else Path("./logs")
    setup_global_tee(log_dir)

    # Validate paths
    target_yaml = Path(args.target_yaml)
    if not target_yaml.exists():
        error(f"Target YAML file not found: {target_yaml}")
        sys.exit(1)

    # Parse target YAML
    projects = parse_target_yaml(target_yaml)
    if not projects:
        error("No projects found in target YAML")
        sys.exit(1)

    # Filter projects if requested
    if args.filter_projects:
        filter_names = set(args.filter_projects.split(","))
        projects = [p for p in projects if p["name"] in filter_names]
        log(f"Filtered to {len(projects)} projects: {filter_names}")

    # Initialize port manager
    port_manager = PortManager(args.start_port)

    # Process projects
    results = []

    if args.max_workers == 1:
        # Sequential processing
        for project in projects:
            result = process_project(project, args, port_manager)
            results.append(result)

            if not result["overall_success"] and not args.continue_on_failure:
                error("Stopping due to failure (use --continue-on-failure to continue)")
                break
    else:
        # Parallel processing
        log(f"Processing {len(projects)} projects with {args.max_workers} workers")

        with ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            future_to_project = {
                executor.submit(process_project, project, args, port_manager): project
                for project in projects
            }

            for future in as_completed(future_to_project):
                project = future_to_project[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    error(f"Exception processing project {project['name']}: {e}")
                    results.append(
                        {
                            "project": project["name"],
                            "crs_test_success": False,
                            "sarif_send_success": False,
                            "cleanup_success": False,
                            "overall_success": False,
                            "error": str(e),
                            "port": None,
                        }
                    )

    # Print summary
    print_summary(results)

    # Save results to CSV if artifacts were checked
    if args.check_artifacts and results:
        log_dir = Path(args.log_dir) if args.log_dir else Path("./logs")
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        csv_path = log_dir / f"e2e_test_results-{ts}.csv"
        save_results_to_csv(results, csv_path)

    # Exit with error code if any projects failed
    failed_projects = [r for r in results if not r["overall_success"]]
    if failed_projects:
        sys.exit(1)
    else:
        log("All projects processed successfully!")
        sys.exit(0)


if __name__ == "__main__":
    main()
