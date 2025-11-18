#!/usr/bin/env python3

import asyncio
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from utils import CPUSlotManager, JobQueue, create_job_id
from loguru import logger


async def test_multi_slot_allocation():
    """Test allocation of multiple slots for jobs needing more cores"""
    logger.info("Testing multi-slot allocation")

    cpu_manager = CPUSlotManager(total_cores=8, cores_per_job=2, start_core=0)

    # Test single core allocation (should use 1 slot)
    job1_id = create_job_id()
    allocation1 = await cpu_manager.allocate(job1_id, 1)
    assert allocation1 == (0, 0), f"Expected (0, 0), got {allocation1}"

    # Test 2-core allocation (should use 1 slot)
    job2_id = create_job_id()
    allocation2 = await cpu_manager.allocate(job2_id, 2)
    assert allocation2 == (2, 3), f"Expected (2, 3), got {allocation2}"

    # Test 3-core allocation (should use 2 slots)
    job3_id = create_job_id()
    allocation3 = await cpu_manager.allocate(job3_id, 3)
    assert allocation3 == (4, 6), f"Expected (4, 6), got {allocation3}"

    # Test 5-core allocation (should use 3 slots, but only 1 slot left)
    job4_id = create_job_id()
    allocation4 = await cpu_manager.allocate(job4_id, 5)
    assert allocation4 is None, "Should fail when not enough slots"

    # Release all jobs to free up all slots
    await cpu_manager.release(job1_id)
    await cpu_manager.release(job2_id)
    await cpu_manager.release(job3_id)

    # Now 5-core allocation should work (needs 3 slots, we have 4 available)
    allocation4 = await cpu_manager.allocate(job4_id, 5)
    assert allocation4 == (0, 4), f"Expected (0, 4), got {allocation4}"

    logger.success("Multi-slot allocation test passed!")


async def test_concurrent_allocation():
    """Test async lock works correctly under concurrent allocation"""
    logger.info("Testing concurrent allocation with async locks")

    cpu_manager = CPUSlotManager(total_cores=8, cores_per_job=2, start_core=0)

    async def allocate_job(cores_needed=2):
        job_id = create_job_id()
        allocation = await cpu_manager.allocate(job_id, cores_needed)
        if allocation is not None:
            await asyncio.sleep(0.1)  # Simulate work
            await cpu_manager.release(job_id)
        return allocation

    # Try to allocate 10 jobs concurrently (more than available slots)
    tasks = [allocate_job() for _ in range(10)]
    results = await asyncio.gather(*tasks)

    # Should get exactly 4 successful allocations (total slots available)
    successful = [r for r in results if r is not None]
    failed = [r for r in results if r is None]

    logger.info(f"Successful allocations: {len(successful)}")
    logger.info(f"Failed allocations: {len(failed)}")

    assert len(successful) == 4, f"Expected 4 successful, got {len(successful)}"
    assert len(failed) == 6, f"Expected 6 failed, got {len(failed)}"

    logger.success("Concurrent allocation test passed!")


async def test_slot_exhaustion_and_reuse():
    """Test behavior when all slots are full and then released"""
    logger.info("Testing slot exhaustion and reuse")

    cpu_manager = CPUSlotManager(total_cores=6, cores_per_job=2, start_core=0)

    # Allocate all slots (should be 3 slots)
    job_ids = []
    for i in range(3):
        job_id = create_job_id()
        allocation = await cpu_manager.allocate(job_id, 2)
        assert allocation is not None, f"Should allocate slot {i}"
        job_ids.append(job_id)

    # Try to allocate one more - should fail
    extra_job_id = create_job_id()
    extra_allocation = await cpu_manager.allocate(extra_job_id, 2)
    assert extra_allocation is None, "Should fail when all slots are full"

    # Release one slot
    released = await cpu_manager.release(job_ids[1])
    assert released is True, "Should successfully release slot"

    # Now allocation should work again
    new_allocation = await cpu_manager.allocate(extra_job_id, 2)
    assert new_allocation is not None, "Should allocate after release"

    logger.success("Slot exhaustion and reuse test passed!")


async def test_invalid_cpu_configuration():
    """Test edge cases with CPU configuration"""
    logger.info("Testing invalid CPU configurations")

    # Test requesting more cores than total available
    cpu_manager = CPUSlotManager(total_cores=4, cores_per_job=2, start_core=0)
    job_id = create_job_id()
    allocation = await cpu_manager.allocate(job_id, 8)
    assert allocation is None, "Should fail when requesting more cores than available"

    # Test with start_core offset
    cpu_manager = CPUSlotManager(total_cores=8, cores_per_job=2, start_core=2)
    status = cpu_manager.get_status()
    assert status["total_slots"] == 3, f"Expected 3 slots, got {status['total_slots']}"

    # Test core ranges with offset
    job_id = create_job_id()
    allocation = await cpu_manager.allocate(job_id, 2)
    assert allocation == (2, 3), f"Expected cores (2, 3), got {allocation}"

    logger.success("Invalid CPU configuration test passed!")


async def test_release_nonexistent_job():
    """Test releasing a job that doesn't exist"""
    logger.info("Testing release of nonexistent job")

    cpu_manager = CPUSlotManager(total_cores=4, cores_per_job=2, start_core=0)

    # Try to release a job that was never allocated
    fake_job_id = create_job_id()
    released = await cpu_manager.release(fake_job_id)
    assert released is False, "Should return False for nonexistent job"

    logger.success("Release nonexistent job test passed!")


async def test_job_queue_with_cores():
    """Test job queue with cores_needed information"""
    logger.info("Testing job queue with cores_needed")

    job_queue = JobQueue()

    # Test job with cores_needed
    job1 = {"job_id": create_job_id(), "target": "test1", "cores_needed": 4}
    await job_queue.add_job(job1)

    next_job = await job_queue.get_next_job()
    assert next_job["cores_needed"] == 4, "Should preserve cores_needed"

    job_queue.mark_running(next_job["job_id"], next_job)
    job_queue.mark_completed(next_job["job_id"])

    status = job_queue.get_status()
    assert status["completed_jobs"] == 1

    logger.success("Job queue with cores test passed!")


async def test_high_concurrency_stress():
    """Stress test with high concurrency and variable core requirements"""
    logger.info("Testing high concurrency stress with variable cores")

    cpu_manager = CPUSlotManager(total_cores=8, cores_per_job=1, start_core=0)

    allocation_count = 0
    release_count = 0

    async def worker():
        nonlocal allocation_count, release_count
        for _ in range(3):  # Each worker tries 3 times
            job_id = create_job_id()
            cores_needed = 1 + (_ % 3)  # 1, 2, or 3 cores
            allocation = await cpu_manager.allocate(job_id, cores_needed)
            if allocation is not None:
                allocation_count += 1
                await asyncio.sleep(0.01)  # Brief work simulation
                released = await cpu_manager.release(job_id)
                if released:
                    release_count += 1
            await asyncio.sleep(0.001)  # Brief pause

    # Run 15 workers concurrently
    tasks = [worker() for _ in range(15)]
    await asyncio.gather(*tasks)

    logger.info(f"Allocations: {allocation_count}, Releases: {release_count}")
    assert allocation_count == release_count, "All allocations should be released"

    # Final state should be clean
    status = cpu_manager.get_status()
    assert status["allocated_slots"] == 0, "No slots should be allocated at end"
    assert status["available_slots"] == 8, "All slots should be available"

    logger.success("High concurrency stress test passed!")


async def main():
    """Run all comprehensive tests"""
    logger.info("Starting comprehensive CPU Manager tests...")

    try:
        await test_multi_slot_allocation()
        await test_concurrent_allocation()
        await test_slot_exhaustion_and_reuse()
        await test_invalid_cpu_configuration()
        await test_release_nonexistent_job()
        await test_job_queue_with_cores()
        await test_high_concurrency_stress()
        logger.success("All comprehensive tests passed!")
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
