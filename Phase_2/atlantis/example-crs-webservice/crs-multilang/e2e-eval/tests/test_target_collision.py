#!/usr/bin/env python3
"""
Test script to verify target collision detection functionality
"""

import asyncio
import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from utils import JobQueue  # noqa: E402


async def test_target_collision_prevention():
    """Test target collision prevention functionality"""
    print("=== Testing Target Collision Prevention ===")

    # Test with collision prevention enabled
    print("\n1. Testing with collision prevention ENABLED:")
    job_queue = JobQueue(prevent_target_collision=True)

    # Add jobs for the same target
    target = "aixcc/c/r2-libxml2"
    jobs = [
        {"job_id": "job1", "target": target, "hash_str": "hash1", "cores_needed": 8},
        {"job_id": "job2", "target": target, "hash_str": "hash2", "cores_needed": 8},
        {"job_id": "job3", "target": target, "hash_str": "hash3", "cores_needed": 8},
    ]

    for job in jobs:
        await job_queue.add_job(job)

    print(f"Added {len(jobs)} jobs for target: {target}")
    print(f"Queue status: {job_queue.get_status()}")

    # Simulate getting jobs and checking collision detection
    job1 = await job_queue.get_next_job()
    print(f"Got first job: {job1['job_id']}")

    # Mark target as running
    job_queue.mark_target_running(target)
    print(f"Marked target {target} as running")
    print(f"Is target running? {job_queue.is_target_running(target)}")

    # Try to get next job - should be queued due to collision
    job2 = await job_queue.get_next_job()
    print(f"Got second job: {job2['job_id']}")

    # Check if it gets queued for the target
    if job_queue.is_target_running(target):
        await job_queue.queue_job_for_target(target, job2)
        print(f"Job {job2['job_id']} queued for busy target")

    print(f"Queue status after collision: {job_queue.get_status()}")

    # Mark target as completed - should dispatch next job
    job_queue.mark_target_completed(target)
    print(f"Marked target {target} as completed")
    print(f"Queue status after completion: {job_queue.get_status()}")

    print("\n2. Testing with collision prevention DISABLED:")
    job_queue_no_collision = JobQueue(prevent_target_collision=False)

    for job in jobs:
        await job_queue_no_collision.add_job(job)

    print(f"Added {len(jobs)} jobs for target: {target}")
    print(f"Queue status: {job_queue_no_collision.get_status()}")

    # Should not track targets when disabled
    print(
        "Is target running (should be False)?"
        f" {job_queue_no_collision.is_target_running(target)}"
    )

    print("\n=== Test completed successfully! ===")


async def test_multiple_targets():
    """Test with multiple different targets"""
    print("\n=== Testing Multiple Targets ===")

    job_queue = JobQueue(prevent_target_collision=True)

    targets = ["aixcc/c/r2-libxml2", "aixcc/c/r2-sqlite3", "aixcc/jvm/r2-zookeeper"]

    jobs = []
    for i, target in enumerate(targets):
        for j in range(2):  # 2 jobs per target
            job = {
                "job_id": f"job_{i}_{j}",
                "target": target,
                "hash_str": f"hash_{i}_{j}",
                "cores_needed": 8,
            }
            jobs.append(job)
            await job_queue.add_job(job)

    print(f"Added {len(jobs)} jobs for {len(targets)} targets")
    print(f"Initial queue status: {job_queue.get_status()}")

    # Start one job per target
    for target in targets:
        job = await job_queue.get_next_job()
        print(f"Started job {job['job_id']} for target {job['target']}")
        job_queue.mark_target_running(job["target"])

    print(f"Status with all targets running: {job_queue.get_status()}")

    # Try to get more jobs - should be queued
    remaining_jobs = []
    while not job_queue.pending.empty():
        job = await job_queue.get_next_job()
        if job_queue.is_target_running(job["target"]):
            await job_queue.queue_job_for_target(job["target"], job)
            print(f"Queued job {job['job_id']} for busy target {job['target']}")
        remaining_jobs.append(job)

    print(f"Status after queuing remaining jobs: {job_queue.get_status()}")

    # Complete one target
    first_target = targets[0]
    job_queue.mark_target_completed(first_target)
    print(f"Completed target {first_target}")
    print(f"Final status: {job_queue.get_status()}")

    print("\n=== Multiple targets test completed! ===")


if __name__ == "__main__":
    asyncio.run(test_target_collision_prevention())
    asyncio.run(test_multiple_targets())
