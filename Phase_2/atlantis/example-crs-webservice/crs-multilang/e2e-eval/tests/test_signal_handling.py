#!/usr/bin/env python3
"""
Test script to verify signal handling and cleanup functionality.
This creates mock CRS jobs and tests the cleanup mechanism.
"""

import asyncio
import os
import signal
import sys

# Add the current directory to Python path to import utils
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from utils import cleanup_running_jobs
from loguru import logger

# Configure logger
logger.remove()
logger.add(sys.stderr, level="INFO")


async def create_mock_job(job_id: str, duration: int = 30):
    """Create a mock CRS job that runs for a specified duration"""
    cmd = f"""
    export CRS_JOB_ID={job_id}
    echo "Mock job {job_id} started at $(date)"
    sleep {duration}
    echo "Mock job {job_id} completed at $(date)"
    """

    process = await asyncio.create_subprocess_shell(
        f"nohup bash -c '{cmd}' &",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await process.wait()
    logger.info(f"Started mock job {job_id} (will run for {duration}s)")


async def test_cleanup():
    """Test the cleanup functionality"""
    logger.info("=== Testing Signal Handling and Cleanup ===")

    # Create some mock jobs
    job_ids = ["test-job-1", "test-job-2", "test-job-3"]

    logger.info("Creating mock CRS jobs...")
    for job_id in job_ids:
        await create_mock_job(job_id, duration=60)  # 60 second jobs

    # Wait a moment for jobs to start
    await asyncio.sleep(2)

    # Check that jobs are running
    result = await asyncio.create_subprocess_exec(
        "ps", "axe", stdout=asyncio.subprocess.PIPE
    )
    stdout, _ = await result.communicate()

    running_jobs = []
    for line in stdout.decode().split("\n"):
        if "CRS_JOB_ID=" in line:
            for job_id in job_ids:
                if f"CRS_JOB_ID={job_id}" in line:
                    running_jobs.append(job_id)

    logger.info(f"Found {len(running_jobs)} running mock jobs: {running_jobs}")

    if not running_jobs:
        logger.error("No mock jobs found running!")
        return False

    # Test cleanup
    logger.info("Testing cleanup functionality...")
    terminated_count = await cleanup_running_jobs()

    logger.info(f"Cleanup terminated {terminated_count} jobs")

    # Verify cleanup worked
    await asyncio.sleep(2)
    result = await asyncio.create_subprocess_exec(
        "ps", "axe", stdout=asyncio.subprocess.PIPE
    )
    stdout, _ = await result.communicate()

    remaining_jobs = []
    for line in stdout.decode().split("\n"):
        if "CRS_JOB_ID=" in line:
            for job_id in job_ids:
                if f"CRS_JOB_ID={job_id}" in line:
                    remaining_jobs.append(job_id)

    if remaining_jobs:
        logger.warning(f"Some jobs still running: {remaining_jobs}")
        return False
    else:
        logger.success("All mock jobs successfully cleaned up!")
        return True


# Global cleanup event for signal coordination
cleanup_event = None

def signal_handler(signum, frame):
    """Signal handler for testing - matches run_eval.py pattern"""
    signal_name = "SIGINT" if signum == signal.SIGINT else f"Signal {signum}"
    logger.warning(f"Received {signal_name}, initiating cleanup of running jobs...")
    if cleanup_event:
        cleanup_event.set()


async def main():
    """Main test function"""
    global cleanup_event
    
    if len(sys.argv) > 1 and sys.argv[1] == "--signal-test":
        # Test signal handling
        logger.info("=== Signal Handling Test Mode ===")
        logger.info("Creating mock jobs, then press Ctrl+C to test cleanup...")

        # Setup cleanup event and signal handler
        cleanup_event = asyncio.Event()
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Create long-running jobs
        job_ids = ["signal-test-1", "signal-test-2"]
        for job_id in job_ids:
            await create_mock_job(job_id, duration=300)  # 5 minute jobs

        logger.info("Mock jobs created. Press Ctrl+C to test signal handling...")

        # Wait for cleanup signal (like the monitoring loop in run_eval.py)
        try:
            while not cleanup_event.is_set():
                await asyncio.sleep(2)
                logger.info("Still running... (press Ctrl+C to test cleanup)")
            
            # Cleanup was requested
            logger.info("Cleanup requested, terminating running jobs...")
            terminated_count = await cleanup_running_jobs()
            logger.success(f"Signal cleanup terminated {terminated_count} jobs")
            
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt caught in main loop")

    else:
        # Test cleanup functionality directly
        success = await test_cleanup()
        if success:
            logger.success("✓ Cleanup test passed!")
            return 0
        else:
            logger.error("✗ Cleanup test failed!")
            return 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Test interrupted by user")
        sys.exit(0)
