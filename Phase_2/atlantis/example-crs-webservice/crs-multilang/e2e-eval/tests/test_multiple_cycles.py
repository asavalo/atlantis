#!/usr/bin/env python3

import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from utils import (
    CPUSlotManager,
    JobQueue,
    dispatch_jobs,
    check_completed_jobs,
    create_job_id,
)
from loguru import logger


async def mock_job_executor(job_dict, *args):
    """Mock job executor that simulates work for 0.5 seconds"""
    job_id = job_dict["job_id"]
    allocation = job_dict.get("allocation")
    if allocation:
        start_core, end_core = allocation
        logger.info(f"Mock job {job_id} running on cores {start_core}-{end_core}")

    # Simulate work
    await asyncio.sleep(0.5)
    logger.success(f"Mock job {job_id} completed")


async def test_multiple_cycles():
    """Test that all jobs complete even with multiple queue cycles"""
    logger.info("=== Testing Multiple Cycles with Queue Overflow ===")

    # Create a small CPU manager (only 2 slots, 1 core each)
    cpu_manager = CPUSlotManager(total_cores=4, cores_per_job=1, start_core=0)
    job_queue = JobQueue()

    # Create 10 jobs (much more than available slots)
    total_jobs = 10
    logger.info(
        f"Creating {total_jobs} jobs for only {cpu_manager.get_status()['total_slots']} slots"
    )

    for i in range(total_jobs):
        job_info = {
            "job_id": create_job_id(),
            "target": f"test-target-{i}",
            "cores_needed": 1,
            "data": f"job-{i}",
        }
        await job_queue.add_job(job_info)

    logger.info(f"Initial queue status: {job_queue.get_status()}")

    # Start background tasks
    monitor_task = asyncio.create_task(check_completed_jobs(cpu_manager, job_queue))
    dispatch_task = asyncio.create_task(
        dispatch_jobs(cpu_manager, job_queue, mock_job_executor)
    )

    # Wait for all jobs to complete
    await asyncio.gather(monitor_task, dispatch_task)

    # Check final status
    final_status = job_queue.get_status()
    cpu_status = cpu_manager.get_status()

    logger.info(f"Final queue status: {final_status}")
    logger.info(f"Final CPU status: {cpu_status}")

    # Verify all jobs completed
    assert (
        final_status["pending_jobs"] == 0
    ), f"Still have pending jobs: {final_status['pending_jobs']}"
    assert (
        final_status["running_jobs"] == 0
    ), f"Still have running jobs: {final_status['running_jobs']}"
    assert (
        final_status["completed_jobs"] == total_jobs
    ), f"Expected {total_jobs} completed, got {final_status['completed_jobs']}"
    assert (
        cpu_status["allocated_slots"] == 0
    ), f"Still have allocated slots: {cpu_status['allocated_slots']}"

    logger.success(f"✅ All {total_jobs} jobs completed successfully!")
    logger.success("✅ Multiple cycles test PASSED!")


async def test_variable_core_requirements():
    """Test jobs with different core requirements over multiple cycles"""
    logger.info("=== Testing Variable Core Requirements ===")

    # Create CPU manager with 8 cores, 2 cores per slot = 4 slots
    cpu_manager = CPUSlotManager(total_cores=8, cores_per_job=2, start_core=0)
    job_queue = JobQueue()

    # Create jobs with different core requirements
    jobs_config = [
        {"cores": 1, "count": 3},  # 3 jobs needing 1 core each (1 slot each)
        {"cores": 2, "count": 2},  # 2 jobs needing 2 cores each (1 slot each)
        {"cores": 4, "count": 2},  # 2 jobs needing 4 cores each (2 slots each)
        {"cores": 6, "count": 1},  # 1 job needing 6 cores (3 slots)
    ]

    total_jobs = sum(config["count"] for config in jobs_config)
    logger.info(f"Creating {total_jobs} jobs with variable core requirements")

    job_counter = 0
    for config in jobs_config:
        for i in range(config["count"]):
            job_info = {
                "job_id": create_job_id(),
                "target": f"var-target-{job_counter}",
                "cores_needed": config["cores"],
                "data": f'job-{job_counter}-{config["cores"]}cores',
            }
            await job_queue.add_job(job_info)
            job_counter += 1

    logger.info(f"Available slots: {cpu_manager.get_status()['total_slots']}")
    logger.info(f"Initial queue status: {job_queue.get_status()}")

    # Start background tasks
    monitor_task = asyncio.create_task(check_completed_jobs(cpu_manager, job_queue))
    dispatch_task = asyncio.create_task(
        dispatch_jobs(cpu_manager, job_queue, mock_job_executor)
    )

    # Wait for completion
    await asyncio.gather(monitor_task, dispatch_task)

    # Verify results
    final_status = job_queue.get_status()
    cpu_status = cpu_manager.get_status()

    logger.info(f"Final queue status: {final_status}")
    logger.info(f"Final CPU status: {cpu_status}")

    assert final_status["completed_jobs"] == total_jobs
    assert final_status["pending_jobs"] == 0
    assert final_status["running_jobs"] == 0
    assert cpu_status["allocated_slots"] == 0

    logger.success(f"✅ All {total_jobs} variable-core jobs completed!")
    logger.success("✅ Variable core requirements test PASSED!")


async def main():
    logger.info("Starting multiple cycles test suite...")

    try:
        await test_multiple_cycles()
        await test_variable_core_requirements()
        logger.success("🎉 ALL MULTIPLE CYCLES TESTS PASSED!")
        logger.info("The system correctly handles:")
        logger.info("  ✅ More jobs than available slots")
        logger.info("  ✅ Multiple queue cycles")
        logger.info("  ✅ Variable core requirements")
        logger.info("  ✅ Complete job execution to finish")

    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
