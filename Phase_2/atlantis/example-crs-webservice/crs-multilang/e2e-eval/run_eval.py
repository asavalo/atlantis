import argparse
import asyncio
import hashlib
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

from dotenv import load_dotenv
from loguru import logger

from config import (
    EVAL_DURATION_SECONDS,
    INPUT_GEN_COMBINATIONS,
    NCPU_PER_RUN,
    PYENV_ENV_NAME,
    TARGETS_CONFIG,
)
from litellm_utils import create_user, delete_user
from utils import (  # fire_and_ignore,
    CPUSlotManager,
    JobInfo,
    JobQueue,
    analyze_experiments_status,
    check_completed_jobs,
    cleanup_incomplete_experiment,
    dispatch_jobs,
    run_subprocess_safe,
)

load_dotenv(".env.secret")

# Configure logger to INFO level
logger.remove()
logger.add(sys.stderr, level="INFO")

# Global cleanup event for signal coordination
cleanup_event = None
interrupt_count = 0


def setup_signal_handlers():
    """Setup signal handlers for graceful cleanup"""
    global cleanup_event, interrupt_count
    cleanup_event = asyncio.Event()
    interrupt_count = 0

    def signal_handler(signum, frame):
        global interrupt_count
        interrupt_count += 1
        signal_name = "SIGINT" if signum == signal.SIGINT else f"Signal {signum}"

        if interrupt_count == 1:
            logger.warning(
                f"Received {signal_name}, initiating cleanup of running jobs..."
            )
            logger.info("Press Ctrl+C again to force immediate exit")
            if cleanup_event:
                cleanup_event.set()
        else:
            logger.error(f"Received {signal_name} again, forcing immediate exit!")
            import sys

            sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    return cleanup_event


def git_timestamp_to_utc(git_timestamp: str) -> str:
    """Convert git timestamp format to UTC ISO format.

    Args:
        git_timestamp: Git timestamp in format like "2025-06-10T12:52:11+00:00" or "2025-06-09T21:17:16-04:00"

    Returns:
        UTC timestamp in ISO format with 'Z' suffix
    """
    try:
        dt = datetime.fromisoformat(git_timestamp.replace("Z", "+00:00"))
        utc_dt = dt.astimezone(timezone.utc)
        return utc_dt.isoformat().replace("+00:00", "Z")
    except Exception:
        return git_timestamp


async def collect_experiment_metadata(multilang_root) -> Dict:
    """Collect git repository metadata for reproducibility from CRS-multilang root"""
    metadata = {
        "experiment_start_time": datetime.now(timezone.utc).isoformat(),
        "timezone": "UTC",
        "git_info": {},
    }

    try:
        # Main repo commit hash
        returncode, stdout, _ = await run_subprocess_safe(
            "git",
            "rev-parse",
            "HEAD",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=multilang_root,
            timeout=10.0,
        )
        if returncode == 0:
            metadata["git_info"]["main_commit"] = stdout.decode().strip()

        # Get commit date in UTC
        returncode, stdout, _ = await run_subprocess_safe(
            "git",
            "show",
            "-s",
            "--format=%cI",
            "HEAD",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=multilang_root,
            timeout=10.0,
        )
        if returncode == 0:
            git_timestamp = stdout.decode().strip()
            metadata["git_info"]["main_commit_date_utc"] = git_timestamp_to_utc(
                git_timestamp
            )

        # Submodule status - this captures all submodule commit hashes
        result = await asyncio.create_subprocess_exec(
            "git",
            "submodule",
            "status",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=multilang_root,
        )
        stdout, _ = await result.communicate()
        if result.returncode == 0:
            submodules_status = stdout.decode().strip()
            metadata["git_info"]["submodules"] = submodules_status

            # Collect submodule commit dates
            submodules_with_dates = []
            for line in submodules_status.split("\n"):
                if line.strip():
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        commit_hash = parts[0].lstrip(" -+")
                        submodule_path = parts[1]

                        # Get commit date for this submodule in UTC
                        try:
                            date_result = await asyncio.create_subprocess_exec(
                                "git",
                                "show",
                                "-s",
                                "--format=%cI",
                                commit_hash,
                                stdin=subprocess.DEVNULL,
                                stdout=asyncio.subprocess.PIPE,
                                stderr=asyncio.subprocess.PIPE,
                                cwd=multilang_root / submodule_path,
                            )
                            date_stdout, _ = await date_result.communicate()
                            if date_result.returncode == 0:
                                git_timestamp = date_stdout.decode().strip()
                                commit_date_utc = git_timestamp_to_utc(git_timestamp)
                                submodules_with_dates.append(
                                    {
                                        "path": submodule_path,
                                        "commit": commit_hash[:8],
                                        "date_utc": commit_date_utc,
                                    }
                                )
                            else:
                                submodules_with_dates.append(
                                    {
                                        "path": submodule_path,
                                        "commit": commit_hash[:8],
                                        "date_utc": "date unavailable",
                                    }
                                )
                        except Exception:
                            submodules_with_dates.append(
                                {
                                    "path": submodule_path,
                                    "commit": commit_hash[:8],
                                    "date_utc": "date unavailable",
                                }
                            )

            metadata["git_info"]["submodules_with_dates"] = submodules_with_dates

        # Get dirty status
        result = await asyncio.create_subprocess_exec(
            "git",
            "status",
            "--porcelain",
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=multilang_root,
        )
        stdout, _ = await result.communicate()
        if result.returncode == 0:
            dirty_files = stdout.decode().strip()
            metadata["git_info"]["dirty"] = bool(dirty_files)
            if dirty_files:
                metadata["git_info"]["dirty_files"] = dirty_files

    except Exception as e:
        logger.warning(f"Failed to collect git metadata: {e}")
        metadata["git_info"]["error"] = str(e)

    return metadata


def log_module_info(experiment_metadata: Dict) -> None:
    """Log git repository and submodule commit information with dates"""
    logger.info(
        "Main commit:"
        f" {experiment_metadata['git_info'].get('main_commit', 'unknown')[:8]}"
    )
    logger.info(
        "Commit date (UTC):"
        f" {experiment_metadata['git_info'].get('main_commit_date_utc', 'unknown')}"
    )

    submodules_with_dates = experiment_metadata["git_info"].get(
        "submodules_with_dates", []
    )
    if submodules_with_dates:
        logger.info("Submodules:")
        for submodule in submodules_with_dates:
            date_info = submodule.get("date_utc", submodule.get("date", "unknown"))
            logger.info(f"  • {submodule['path']}: {submodule['commit']} ({date_info})")


async def build_crs(multilang_root: Path) -> None:
    cmd = ["python3", "run.py", "run", "--target", "aixcc/c/mock-c", "--test"]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=multilang_root,
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            logger.error(f"Base image build failed: {stderr.decode()}")
            raise Exception(f"Base image build failed: {stderr.decode()}")
        else:
            logger.success("Base image build completed")
    except Exception as e:
        logger.error(f"Base image build error: {e}")
        raise


async def check_docker_image_exists(target: str) -> bool:
    """Check if Docker image for target already exists"""
    image_name = f"aixcc-afc/{target}"

    try:
        process = await asyncio.create_subprocess_exec(
            "docker",
            "image",
            "inspect",
            image_name,
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return process.returncode == 0
    except Exception as e:
        logger.debug(f"Error checking Docker image for {target}: {e}")
        return False


async def sync_artifacts_back(temp_root: Path, main_root: Path, target: str) -> None:
    """Sync artifacts from temp build back to main directory"""
    temp_artifacts = temp_root / "libs" / "oss-fuzz" / "build" / "artifacts" / target
    main_artifacts = main_root / "libs" / "oss-fuzz" / "build" / "artifacts" / target

    if temp_artifacts.exists():
        main_artifacts.parent.mkdir(parents=True, exist_ok=True)
        cmd = [
            "rsync",
            "-a",
            "--ignore-errors",
            "--partial",
            f"{temp_artifacts}/",
            str(main_artifacts),
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                logger.info(f"Synced artifacts for {target} back to main directory")
            else:
                logger.warning(
                    f"Failed to sync artifacts for {target}: {stderr.decode()}"
                )
        except Exception as e:
            logger.error(f"Error syncing artifacts for {target}: {e}")
    else:
        logger.warning(f"No artifacts found for {target} in temp directory")


async def build_cp(
    multilang_root: Path, target: str, skip_existing_images: bool = False
) -> None:
    # Check if Docker image already exists (if option is enabled)
    if skip_existing_images:
        if await check_docker_image_exists(target):
            logger.info(
                f"Docker image aixcc-afc/{target} already exists, skipping build"
            )
            return

    # # Create temp directory for this build
    # temp_build_root = generate_temp_multilang_path(
    #     target, f"build-{target.replace('/', '-')}"
    # )

    try:
        # # Create temp multilang root for isolated build
        # temp_path = await create_temp_multilang_root(
        #     multilang_root, target, "build", temp_build_root
        # )

        cmd = [
            "python3",
            "run.py",
            "run",
            "--target",
            target,
            "--build-only",
            "--skip-build-crs",
        ]
        logger.info(f"Build started for: {target}")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=multilang_root,
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            logger.error(f"Build failed for {target}: {stderr.decode()}")
            logger.warning("Continuing with other builds...")
        else:
            # Sync artifacts back to main directory
            # await sync_artifacts_back(temp_build_root, multilang_root, target)
            logger.success(f"Build completed for target: {target}")

    except Exception as e:
        logger.error(f"Build error for {target}: {e}")
        logger.warning("Continuing with other builds...")
    finally:
        pass
        # # Clean up temp build directory
        # if temp_build_root.exists():
        #     temp_dir = temp_build_root.parent
        #     try:
        #         fire_and_ignore(f"sudo rm -rf {temp_dir}")
        #         logger.debug(f"Cleaning up temp build directory: {temp_dir}")
        #     except Exception as e:
        #         logger.warning(f"Failed to cleanup temp directory for {target}: {e}")


def write_configs(
    out_dir: Path, target: str, harnesses: List[str], cores_per_cp: bool = False
) -> List[Tuple[str, Path]]:
    ret = []

    # Calculate CPU requirement
    total_cores = multiprocessing.cpu_count()

    if cores_per_cp:
        # Use NCPU_PER_RUN cores per CP (not per harness)
        requested_cores = NCPU_PER_RUN
        allocated_cores = min(requested_cores, total_cores)

        if requested_cores > total_cores:
            logger.warning(
                f"Target {target} requests {requested_cores} cores (NCPU_PER_RUN per"
                f" CP), but system only has {total_cores} cores. Limiting to"
                f" {allocated_cores} cores."
            )
    else:
        # Use automatic calculation based on harnesses
        requested_cores = len(harnesses) * NCPU_PER_RUN
        allocated_cores = min(requested_cores, total_cores)

        if requested_cores > total_cores:
            logger.warning(
                f"Target {target} requests {requested_cores} cores "
                f"({len(harnesses)} harnesses × {NCPU_PER_RUN}), "
                f"but system only has {total_cores} cores. "
                f"Limiting to {allocated_cores} cores."
            )

    config: Dict = {
        "ncpu": allocated_cores,
        "modules": ["uniafl"],
        "others": {"input_gens": []},
        "target_harnesses": harnesses,
    }

    for comb in INPUT_GEN_COMBINATIONS:
        hash_str = hashlib.sha256(str(comb).encode()).hexdigest()[:16]
        config["others"]["input_gens"] = comb

        config_dir = out_dir / "configs" / target
        config_dir.mkdir(parents=True, exist_ok=True)

        config_file = config_dir / f"{hash_str}.json"

        # Find which input gen combination this is
        comb_letter = chr(65 + INPUT_GEN_COMBINATIONS.index(comb))
        logger.info(f"Config {hash_str[:8]} ({comb_letter}): {config_file}")
        logger.info(f"  • Input gens: {comb}")

        if cores_per_cp:
            logger.info(
                f"  • Cores: {NCPU_PER_RUN} per CP → {allocated_cores} allocated"
            )
        else:
            logger.info(
                f"  • Harnesses: {len(harnesses)} × {NCPU_PER_RUN} ="
                f" {requested_cores} cores (allocated: {allocated_cores} cores)"
            )

        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)

        ret.append((hash_str, config_file))

    return ret


def check_litellm_credentials() -> None:
    """Check for required LITELLM environment variables and prompt user if missing"""
    litellm_master_key = os.getenv("LITELLM_MASTER_KEY")
    litellm_url = os.getenv("LITELLM_URL")

    if not litellm_master_key or not litellm_url:
        logger.error("Missing required LITELLM environment variables!")
        logger.error("Required variables:")
        logger.error(
            f"  • LITELLM_MASTER_KEY: {'✓ Set' if litellm_master_key else '✗ Missing'}"
        )
        logger.error(f"  • LITELLM_URL: {'✓ Set' if litellm_url else '✗ Missing'}")
        logger.error("")
        logger.error(
            "Please ensure .env.secret file contains these variables or set them"
            " manually:"
        )
        logger.error("  export LITELLM_MASTER_KEY=your_master_key_here")
        logger.error("  export LITELLM_URL=your_url_here")

        try:
            response = (
                input("\nDo you want to continue anyway? (y/N): ").strip().lower()
            )
            if response not in ["y", "yes"]:
                logger.info("Exiting...")
                sys.exit(1)
            else:
                logger.warning("Continuing without LITELLM credentials.")
        except (KeyboardInterrupt, EOFError):
            logger.info("\nExiting...")
            sys.exit(1)
    else:
        logger.info("LITELLM credentials found ✓")


def check_output_directory(out_dir: Path) -> None:
    """Check if output directory exists and prompt user for overwrite confirmation"""
    if out_dir.exists():
        logger.warning(f"Output directory already exists: {out_dir}")

        # Check if directory has contents
        try:
            contents = list(out_dir.iterdir())
            if contents:
                logger.warning(f"Directory contains {len(contents)} items")
                for item in contents[:5]:  # Show first 5 items
                    logger.warning(f"  • {item.name}")
                if len(contents) > 5:
                    logger.warning(f"  • ... and {len(contents) - 5} more items")
        except PermissionError:
            logger.warning("Cannot list directory contents (permission denied)")

        try:
            response = (
                input(f"\nOverwrite existing directory '{out_dir}'? (y/N): ")
                .strip()
                .lower()
            )
            if response not in ["y", "yes"]:
                logger.info("Exiting...")
                sys.exit(1)
            else:
                logger.info("Proceeding with existing output directory")
        except (KeyboardInterrupt, EOFError):
            logger.info("\nExiting...")
            sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run CRS-multilang with dynamic CPU scheduling"
    )
    parser.add_argument(
        "--multilang-root",
        type=Path,
        default="../../",
        help="Path to CRS-multilang directory (default: ../../)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default="./eval_out",
        help="Output directory (default: ./eval_out)",
    )
    parser.add_argument(
        "--start-core-idx", type=int, default=0, help="Starting core index (default: 0)"
    )
    parser.add_argument(
        "--cores-per-cp",
        action="store_true",
        help="Use NCPU_PER_RUN cores per CP instead of per harness",
    )
    parser.add_argument(
        "--start-other-services",
        action="store_true",
        help="Start other services during evaluation",
    )
    parser.add_argument(
        "--copy-workdir",
        action="store_true",
        help="Copy working directory during evaluation",
    )
    parser.add_argument(
        "--dont-cleanup-temps",
        action="store_true",
        help=(
            "Don't clean up temporary directories after completion (default: cleanup"
            " enabled)"
        ),
    )
    parser.add_argument(
        "--skip-existing-images",
        action="store_true",
        help=(
            "Skip building targets if Docker image already exists (default: always"
            " build)"
        ),
    )
    return parser.parse_args()


def generate_temp_multilang_path(target: str, hash_str: str) -> Path:
    """Generate temp directory path without creating it"""
    import uuid

    unique_id = str(uuid.uuid4())[:8]
    temp_dir = (
        Path(tempfile.gettempdir())
        / f"crs-{target.replace('/', '-')}-{hash_str}-{unique_id}"
    )
    return temp_dir / "CRS-multilang"


async def create_temp_multilang_root(
    multilang_root: Path, target: str, hash_str: str, temp_multilang_root: Path
) -> Path:
    """Create the actual temp directory and sync files"""
    temp_dir = temp_multilang_root.parent
    temp_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Creating temp directory: {temp_multilang_root}")

    cmd = [
        "rsync",
        # "--exclude=.git",
        # "--exclude=.github",
        "--exclude=tags",
        "--exclude=local-testing",
        # "--exclude=target",
        "--exclude=*.pyc",
        "--exclude=__pycache__",
        "--exclude=blob-gen/multilang-llm-agent/results",
        "--exclude=.mypy_cache",
        "--exclude=benchmarks/projects",
        "--exclude=libs/oss-fuzz/build",
        "-a",
        "--delete",
        "--ignore-errors",
        "--partial",
        f"{multilang_root}/",
        str(temp_multilang_root),
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode not in [0, 23]:
            logger.error(f"rsync failed: {stderr.decode()}")
    except Exception as e:
        logger.error(f"Failed to clone: {e}")

    # Copy specific target project
    target_src = multilang_root / "benchmarks" / "projects" / target
    target_dst = temp_multilang_root / "benchmarks" / "projects" / target

    if target_src.exists():
        try:
            target_dst.parent.mkdir(parents=True, exist_ok=True)
            target_cmd = [
                "rsync",
                "-a",
                "--ignore-errors",
                "--partial",
                f"{target_src}/",
                str(target_dst),
            ]
            process = await asyncio.create_subprocess_exec(
                *target_cmd,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                logger.success(f"Prepared workspace for {target}")
            else:
                logger.error(f"Error syncing target: {stderr.decode()}")
        except Exception as e:
            logger.error(f"Error syncing target: {e}")

    # Copy target-specific artifacts
    artifacts_src = (
        multilang_root / "libs" / "oss-fuzz" / "build" / "artifacts" / target
    )
    artifacts_dst = (
        temp_multilang_root / "libs" / "oss-fuzz" / "build" / "artifacts" / target
    )

    if artifacts_src.exists():
        try:
            artifacts_dst.parent.mkdir(parents=True, exist_ok=True)
            artifacts_cmd = [
                "rsync",
                "-a",
                "--ignore-errors",
                "--partial",
                f"--exclude=libs/oss-fuzz/build/artfifacts/{target}/eval_result",
                f"--exclude=libs/oss-fuzz/build/artfifacts/{target}/workdir_result",
                f"{artifacts_src}/",
                str(artifacts_dst),
            ]
            process = await asyncio.create_subprocess_exec(
                *artifacts_cmd,
                stdin=subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                logger.success(f"Copied artifacts for {target}")
            else:
                logger.error(f"Error syncing artifacts: {stderr.decode()}")
        except Exception as e:
            logger.error(f"Error syncing artifacts: {e}")

    return temp_multilang_root


async def execute_job(job_dict: Dict, args) -> None:
    """Execute a job with dynamically allocated CPU cores"""
    # Extract allocation info from job_dict
    allocation = job_dict.get("allocation")
    if not allocation:
        logger.error("No CPU allocation found in job")
        return

    start_core, end_core = allocation

    # Create JobInfo from job_dict (excluding allocation)
    job_data = {k: v for k, v in job_dict.items() if k not in ["allocation"]}
    job_info = JobInfo(**job_data)

    # LiteLLM API key is now generated automatically in JobInfo.__post_init__()
    job_api_key = job_info.litellm_api_key

    # Create temp directory now (during execution)
    await create_temp_multilang_root(
        args.multilang_root,
        job_info.target,
        job_info.hash_str,
        job_info.temp_multilang_root,
    )

    # Build environment dictionary
    env_dict = os.environ.copy()  # Start with current environment
    env_dict.update(
        {key: value for key, value in os.environ.items() if key.startswith("LITELLM_")}
    )
    env_dict["CRS_JOB_ID"] = job_info.job_id

    # Use job-specific API key if available
    if job_api_key:
        env_dict["LITELLM_KEY"] = job_api_key

    output_dir = args.out_dir / "results" / job_info.hash_str

    eval_cmd = (
        "python3 run.py eval "
        f"--start-core-id {start_core} "
        f"--target {job_info.target} "
        f"--config {job_info.config_file} "
        f"--seconds {EVAL_DURATION_SECONDS} "
        f"--out {output_dir} "
        "--skip-build "
        "--skip-build-crs "
        "--log "
        + ("--start-other-services " if args.start_other_services else "")
        + (
            "--delta-mode "
            if "-diff-" in job_info.target or "-delta-" in job_info.target
            else ""
        )
        + ("--copy-workdir " if args.copy_workdir else "")
    )

    experiment_name = f"{job_info.target.replace('/', '-')}-{job_info.hash_str}"

    full_cmd = (
        f"cd {job_info.temp_multilang_root} "
        f"&& pyenv local {PYENV_ENV_NAME} "
        f"&& {eval_cmd}"
    )

    # Setup stdout logging
    stdout_dir = args.out_dir / "stdout" / job_info.target
    stdout_dir.mkdir(parents=True, exist_ok=True)
    stdout_file = stdout_dir / f"{job_info.hash_str}.txt"

    # Setup resource usage monitoring
    resource_dir = args.out_dir / "resource_usage" / job_info.target
    resource_dir.mkdir(parents=True, exist_ok=True)
    resource_usage_file = resource_dir / f"{job_info.hash_str}.json"

    # Start mpstat monitoring for allocated cores (5-minute intervals)
    core_list = ",".join(str(i) for i in range(start_core, end_core + 1))
    mpstat_cmd = f"mpstat -P {core_list} 300 -o JSON > {resource_usage_file}"

    # Run mpstat with same job ID environment
    mpstat_env = env_dict.copy()
    mpstat_env["CRS_JOB_ID"] = job_info.job_id
    mpstat_env["CRS_MONITOR_TYPE"] = "mpstat"

    # Start mpstat as background process
    mpstat_full_cmd = f"nohup {mpstat_cmd} 2>&1 &"
    subprocess.run(mpstat_full_cmd, shell=True, env=mpstat_env)

    # Execute with nohup to properly detach from parent process
    # This prevents event loop warnings when the main process exits
    final_cmd = f"nohup bash -c '{full_cmd}' > {stdout_file} 2>&1 &"

    # Use subprocess.run instead of asyncio since we want complete detachment
    subprocess.run(final_cmd, shell=True, env=env_dict)

    # Process runs completely independently - monitoring via CRS_JOB_ID

    # Load config to get input gen combination
    with open(job_info.config_file, "r") as f:
        config_data = json.load(f)
    input_gens = config_data["others"]["input_gens"]
    comb_letter = chr(65 + INPUT_GEN_COMBINATIONS.index(input_gens))

    logger.success(f"Started: {experiment_name} (cores {start_core}-{end_core})")
    logger.info(f"  • Job ID: {job_info.job_id}")
    logger.info(f"  • Config: {job_info.config_file}")
    logger.info(f"  • Target: {job_info.target}")
    logger.info(f"  • Input gens ({comb_letter}): {input_gens}")
    logger.info(f"  • Harnesses: {len(config_data['target_harnesses'])}")
    logger.info(f"  • Stdout: {stdout_file}")
    logger.info(f"  • Results: {output_dir}")
    logger.info(f"  • Resource monitoring: {resource_usage_file}")


def main():
    args = parse_args()
    args.multilang_root = args.multilang_root.resolve()
    args.out_dir = args.out_dir.resolve()

    if not args.multilang_root.is_dir():
        raise ValueError(f"Invalid directory: {args.multilang_root}")
    if not args.multilang_root.name == "CRS-multilang":
        raise ValueError(f"Invalid directory: {args.multilang_root}")

    check_litellm_credentials()
    check_output_directory(args.out_dir)

    total_cores = multiprocessing.cpu_count()
    logger.info("Experiment Configuration:")
    logger.info(f"  • Starting from core: {args.start_core_idx}")
    if args.cores_per_cp:
        logger.info(f"  • Cores per CP: {NCPU_PER_RUN} (fixed)")
    else:
        logger.info(f"  • Cores per harness: {NCPU_PER_RUN}")
    logger.info(f"  • Total system cores: {total_cores}")
    logger.info(f"  • Experiment duration: {EVAL_DURATION_SECONDS}s")

    # Filter valid targets
    valid_targets = {
        target: harnesses for target, harnesses in TARGETS_CONFIG.items() if harnesses
    }

    logger.info(f"Processing targets: {list(valid_targets.keys())}")
    logger.info("Input generation combinations:")
    for i, comb in enumerate(INPUT_GEN_COMBINATIONS, 1):
        logger.info(f"  • {chr(64+i)}: {comb}")

    # Phase 1: Setup configs
    logger.info("=== PHASE 1: Setting up configs ===")
    experiment_info = {}
    for target, harnesses_list in valid_targets.items():
        configs = write_configs(args.out_dir, target, harnesses_list, args.cores_per_cp)
        experiment_info[target] = configs

    # Phase 1.2: Collect and save experiment metadata
    logger.info("=== PHASE 1.2: Collecting experiment metadata ===")

    # Change to CRS-multilang root directory for git operations

    try:
        experiment_metadata = asyncio.run(
            collect_experiment_metadata(args.multilang_root)
        )

        # Save to eval_dir/metadata.json
        metadata_file = args.out_dir / "metadata.json"
        args.out_dir.mkdir(parents=True, exist_ok=True)

        with open(metadata_file, "w") as f:
            json.dump(experiment_metadata, f, indent=2)

        logger.success(f"Saved experiment metadata to {metadata_file}")

        # Use separate function to log submodule information
        log_module_info(experiment_metadata)

        # if experiment_metadata["git_info"].get("dirty"):
        #     logger.warning("Repository has uncommitted changes!")

    except Exception as e:
        logger.error(f"Failed to collect experiment metadata: {e}")

    # Phase 1.5: Analyze experiment status
    logger.info("=== PHASE 1.5: Analyzing experiment status ===")
    status_summary = analyze_experiments_status(args.out_dir, experiment_info)

    total_planned = sum(len(experiments) for experiments in status_summary.values())
    completed_count = len(status_summary["completed"])
    incomplete_count = len(status_summary["incomplete"])
    not_started_count = len(status_summary["not_started"])

    logger.info(
        f"Found {total_planned} planned experiments across {len(valid_targets)} targets"
    )
    logger.info(f"  • Completed: {completed_count} experiments (skipping)")
    logger.info(f"  • Incomplete: {incomplete_count} experiments (cleaning up)")
    logger.info(f"  • Not started: {not_started_count} experiments (will run)")

    # Clean up incomplete experiments
    if incomplete_count > 0:
        logger.info("Cleaning up incomplete experiments:")
        cleaned_count = 0
        for target, hash_str, config_file in status_summary["incomplete"]:
            if cleanup_incomplete_experiment(args.out_dir, target, hash_str):
                cleaned_count += 1
        logger.info(f"Successfully cleaned up {cleaned_count} incomplete experiments")

    # Filter out completed experiments from experiment_info
    filtered_experiment_info = {}
    for target, experiment_configs in experiment_info.items():
        filtered_configs = []
        for hash_str, config_file in experiment_configs:
            # Only keep experiments that are not completed
            if not any(
                t == target and h == hash_str for t, h, _ in status_summary["completed"]
            ):
                filtered_configs.append((hash_str, config_file))

        if filtered_configs:  # Only include targets that have remaining experiments
            filtered_experiment_info[target] = filtered_configs

    # Update experiment_info to only include non-completed experiments
    experiment_info = filtered_experiment_info
    remaining_experiments = sum(len(configs) for configs in experiment_info.values())

    if remaining_experiments == 0:
        logger.success("All experiments are already completed! Nothing to run.")
        return

    logger.info(f"Will run {remaining_experiments} remaining experiments")

    # Phase 2: Build base image
    logger.info("=== PHASE 2: Building base image ===")
    try:
        asyncio.run(build_crs(args.multilang_root))
    except Exception as e:
        logger.error(f"Base image build failed: {e}")
        exit(1)

    # Phase 3: Build targets
    logger.info("=== PHASE 3: Building targets ===")

    async def run_builds():
        # Only build targets that have remaining experiments
        targets_to_build = list(experiment_info.keys())
        if targets_to_build:
            logger.info(
                f"Building {len(targets_to_build)} targets with remaining experiments"
            )
            if args.skip_existing_images:
                logger.info("Docker image checking enabled - will skip existing images")
            build_tasks = [
                build_cp(args.multilang_root, target, args.skip_existing_images)
                for target in targets_to_build
            ]
            await asyncio.gather(*build_tasks, return_exceptions=True)
        else:
            logger.info("No targets to build (all experiments completed)")

    asyncio.run(run_builds())

    # Phase 4: Dynamic job scheduling
    logger.info("=== PHASE 4: Dynamic job scheduling ===")

    async def run_experiments():
        # Setup signal handlers
        cleanup_event = setup_signal_handlers()

        # Create process user for LiteLLM
        process_user_id = None
        if args.start_other_services:
            try:
                process_user_id = create_user()
                logger.success(f"Created process user: {process_user_id}")
            except Exception as e:
                logger.error(f"Failed to create process user: {e}")
                logger.error("Exiting due to user creation failure")
                sys.exit(1)

        try:
            total_cores = multiprocessing.cpu_count()
            cpu_manager = CPUSlotManager(total_cores, NCPU_PER_RUN, args.start_core_idx)

            # Enable target collision prevention only when --start-other-services is used
            prevent_collision = args.start_other_services
            job_queue = JobQueue(prevent_target_collision=prevent_collision)

            if prevent_collision:
                logger.info(
                    "Target collision prevention enabled (--start-other-services"
                    " detected)"
                )
            else:
                logger.info("Target collision prevention disabled")

            # Create all jobs (temp directories will be created during execution)
            total_jobs = 0
            for target, experiment_configs in experiment_info.items():
                for hash_str, config_file in experiment_configs:
                    # Generate temp path but don't create directory yet
                    temp_multilang_root = generate_temp_multilang_path(target, hash_str)

                    with open(config_file, "r") as f:
                        config_data = json.load(f)
                    cores_needed = config_data["ncpu"]

                    job_info = JobInfo(
                        target=target,
                        hash_str=hash_str,
                        config_file=config_file,
                        temp_multilang_root=temp_multilang_root,
                        cores_needed=cores_needed,
                        user_id=process_user_id,  # Set the process user ID
                        start_other_services=args.start_other_services,
                    )

                    job_dict = job_info.to_dict()

                    await job_queue.add_job(job_dict)
                    total_jobs += 1

            logger.info(f"Created {total_jobs} jobs")
            logger.info(f"Available slots: {cpu_manager.get_status()['total_slots']}")

            # Start monitoring and dispatching
            should_cleanup = not args.dont_cleanup_temps
            monitor_task = asyncio.create_task(
                check_completed_jobs(
                    cpu_manager, job_queue, cleanup_event, should_cleanup, args.out_dir
                )
            )
            dispatch_task = asyncio.create_task(
                dispatch_jobs(
                    cpu_manager,
                    job_queue,
                    execute_job,
                    args,
                    cleanup_event=cleanup_event,
                )
            )

            await asyncio.gather(monitor_task, dispatch_task)

            logger.info("All experiments completed!")

            # Get final status from both managers
            cpu_status = cpu_manager.get_status()
            job_status = job_queue.get_status()

            return {**cpu_status, **job_status}

        finally:
            # Cleanup process user
            if process_user_id:
                try:
                    # Delete the process user
                    if delete_user(process_user_id):
                        logger.success(f"Deleted process user: {process_user_id}")
                    else:
                        logger.warning(
                            f"Failed to delete process user: {process_user_id}"
                        )

                except Exception as e:
                    logger.error(f"Error during process user cleanup: {e}")

    try:
        final_status = asyncio.run(run_experiments())
        logger.info(f"Final status: {final_status}")
    except Exception as e:
        logger.error(f"Error in experiments: {e}")

    # Phase 5: Generate aggregate ZIP files (only if not interrupted)
    # Check both the exception-based flag and the signal handler state
    status_summary = analyze_experiments_status(args.out_dir, experiment_info)
    total_planned = sum(len(experiments) for experiments in status_summary.values())
    completed_count = len(status_summary["completed"])
    # incomplete_count = len(status_summary["incomplete"])
    # not_started_count = len(status_summary["not_started"])
    if total_planned == completed_count:
        logger.info("=== PHASE 5: Generating aggregate ZIP files ===")
        try:
            from generate_zips import generate_aggregate_zips

            success = generate_aggregate_zips(args.out_dir, args.multilang_root)
            if success:
                logger.success("Generated aggregate ZIP files")
            else:
                logger.warning("Failed to generate some aggregate ZIP files")
        except Exception as e:
            logger.error(f"Error generating aggregate ZIP files: {e}")
    else:
        logger.info("Skipping ZIP generation due to incomplete experiments")

    logger.info("Dynamic job scheduling completed!")


if __name__ == "__main__":
    main()
