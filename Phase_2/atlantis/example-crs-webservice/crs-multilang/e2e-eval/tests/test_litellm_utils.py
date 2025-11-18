#!/usr/bin/env python3
"""
Test script for LiteLLM utilities
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from loguru import logger

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

# Import our utilities
from litellm_utils import (  # noqa: E402
    create_user,
    delete_key,
    delete_user,
    generate_key,
    get_key_info,
    get_key_stats,
    get_user_daily_activity,
    load_key_stats,
    save_key_stats,
)

# Load environment variables
load_dotenv(".env.secret")


def test_litellm_utils():
    """Test the LiteLLM utilities functions"""

    # Check environment variables
    litellm_master_key = os.getenv("LITELLM_MASTER_KEY")
    litellm_url = os.getenv("LITELLM_URL")

    if not litellm_master_key or not litellm_url:
        logger.error("Missing required environment variables:")
        logger.error(f"  LITELLM_MASTER_KEY: {'✓' if litellm_master_key else '✗'}")
        logger.error(f"  LITELLM_URL: {'✓' if litellm_url else '✗'}")
        return False

    logger.info("Environment variables found ✓")
    logger.info(f"LITELLM_URL: {litellm_url}")

    # Test job ID
    test_job_id = "test-job-12345"
    process_user_id = None

    try:
        # Test 1: Create process user
        logger.info("=== Test 1: Create Process User ===")
        process_user_id = create_user()
        logger.success(f"Created process user: {process_user_id}")

        # Test 2: Generate key for user
        logger.info("=== Test 2: Generate Key for User ===")
        api_key = generate_key(test_job_id, process_user_id)
        logger.success(f"Generated key: {api_key}")

        # Test 3: Get key stats
        logger.info("=== Test 3: Get Key Stats ===")
        stats = get_key_stats(api_key)
        if stats:
            logger.success(f"Retrieved stats: {stats}")
        else:
            logger.warning("No stats retrieved (this might be normal for new keys)")

        # Test 4: Save key stats
        logger.info("=== Test 4: Save Key Stats ===")
        test_eval_dir = Path("./test_eval_out")
        test_target = "test/target"
        test_config_hash = "abcd1234"

        # Create some dummy stats if none were retrieved
        if not stats:
            stats = {"requests": 0, "cache_hits": 0, "total_spent": 0.0, "errors": 0}

        save_key_stats(test_eval_dir, test_target, test_config_hash, stats)

        # Check if file was created
        expected_file = (
            test_eval_dir / "metadata" / test_target / f"{test_config_hash}.json"
        )
        if expected_file.exists():
            logger.success(f"Stats saved to: {expected_file}")
            with open(expected_file, "r") as f:
                saved_data = f.read()
                logger.info(f"Saved content: {saved_data}")
        else:
            logger.error(f"Stats file not created: {expected_file}")

        # Test 5: Load key stats
        logger.info("=== Test 5: Load Key Stats ===")
        loaded_stats = load_key_stats(test_eval_dir, test_target, test_config_hash)
        if loaded_stats:
            logger.success(f"Loaded stats: {loaded_stats}")
            # Verify some key fields
            if loaded_stats.get("job_id") == test_job_id:
                logger.success("Job ID matches ✓")
            if loaded_stats.get("target") == test_target:
                logger.success("Target matches ✓")
            if loaded_stats.get("config_hash") == test_config_hash:
                logger.success("Config hash matches ✓")
        else:
            logger.error("Failed to load stats")

        # Test 6: Get user daily activity
        logger.info("=== Test 6: Get User Daily Activity ===")
        user_activity = get_user_daily_activity(api_key)
        if user_activity:
            logger.success(f"Retrieved user activity: {user_activity}")
        else:
            logger.warning(
                "No user activity retrieved (this might be normal for new users)"
            )

        # Test 7: Get key info
        logger.info("=== Test 7: Get Key Info ===")
        key_info = get_key_info(api_key)
        if key_info:
            logger.success(f"Retrieved key info: {key_info}")
        else:
            logger.warning("No key info retrieved (this might be normal for new keys)")

        # Test 8: Delete key
        logger.info("=== Test 8: Delete Key ===")
        if delete_key(api_key):
            logger.success("Key deleted successfully")
        else:
            logger.warning("Key deletion failed or key not found")

        logger.success("All tests completed!")
        return True

    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False

    finally:
        # Test 9: Delete process user (cleanup)
        if process_user_id:
            logger.info("=== Test 9: Delete Process User (Cleanup) ===")
            if delete_user(process_user_id):
                logger.success(f"Process user {process_user_id} deleted successfully")
            else:
                logger.warning(f"Failed to delete process user {process_user_id}")


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, level="INFO")

    success = test_litellm_utils()
    sys.exit(0 if success else 1)
