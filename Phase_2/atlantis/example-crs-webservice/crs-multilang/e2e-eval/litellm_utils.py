import json
import os
import time
from pathlib import Path
from typing import Dict, Optional

import requests
from loguru import logger


def create_user(team_id: str = "4dc78d7f-c2e3-476b-a7bb-02b2b8ecfa8c") -> str:
    """Create a temporary user for the process, returns user_id"""
    litellm_url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")

    if not litellm_url or not master_key:
        raise ValueError(
            "LITELLM_URL and LITELLM_MASTER_KEY environment variables are required"
        )

    # Create unique user alias with timestamp
    timestamp = int(time.time())
    user_id = f"e2e-eval-{timestamp}"

    payload = {
        "user_id": user_id,
        "team_id": team_id,
        "auto_create_key": False,
    }

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            f"{litellm_url}/user/new", headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()

        data = response.json()
        user_id = data.get("user_id")

        if not user_id:
            raise ValueError(f"Failed to create user: {data}")

        logger.info(f"Created process user: {user_id}")
        return user_id

    except requests.RequestException as e:
        logger.error(f"Failed to create process user {user_id}: {e}")
        raise


def delete_user(user_id: str) -> bool:
    """Delete a process user"""
    litellm_url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")

    if not litellm_url or not master_key:
        logger.error(
            "LITELLM_URL and LITELLM_MASTER_KEY environment variables are required"
        )
        return False

    payload = {"user_ids": [user_id]}

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            f"{litellm_url}/user/delete", headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()

        logger.info(f"Successfully deleted process user: {user_id}")
        return True

    except requests.RequestException as e:
        logger.error(f"Failed to delete process user {user_id}: {e}")
        return False


def get_user_daily_activity(
    api_key: str, start_date: str = "2025-06-01", end_date: str = "2025-08-01"
) -> Optional[Dict]:
    """Get comprehensive user activity data"""
    litellm_url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")

    if not litellm_url or not master_key:
        logger.error(
            "LITELLM_URL and LITELLM_MASTER_KEY environment variables are required"
        )
        return None

    payload = {
        # "api_key": api_key,
        "start_date": start_date,
        "end_date": end_date,
        "page_size": 1000,
    }

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        response = requests.get(
            f"{litellm_url}/user/daily/activity",
            headers=headers,
            params=payload,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        logger.debug(f"Retrieved daily activity for user {api_key}")
        return data

    except requests.RequestException as e:
        logger.error(f"Failed to get daily activity for user {api_key}: {e}")
        return None


def generate_key(
    job_id: str, user_id: str, team_id: str = "4dc78d7f-c2e3-476b-a7bb-02b2b8ecfa8c"
) -> str:
    """Generate a new LiteLLM API key for a specific user"""
    litellm_url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")

    if not litellm_url or not master_key:
        raise ValueError(
            "LITELLM_URL and LITELLM_MASTER_KEY environment variables are required"
        )

    key_alias = f"e2e-eval-{job_id}"

    # Generate key with proper parameters
    payload = {
        "key_alias": key_alias,
        "team_id": team_id,
        "user_id": user_id,
        "models": ["all-team-models"],
    }

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            f"{litellm_url}/key/generate", headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()

        data = response.json()
        api_key = data.get("key")

        if not api_key:
            raise ValueError(f"Failed to generate key: {data}")

        logger.info(f"Generated LiteLLM key for job {job_id}: {key_alias}")
        return api_key

    except requests.RequestException as e:
        logger.error(f"Failed to generate LiteLLM key for job {job_id}: {e}")
        raise


def delete_key(api_key: str) -> bool:
    """Delete a LiteLLM API key"""
    litellm_url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")

    if not litellm_url or not master_key:
        logger.error(
            "LITELLM_URL and LITELLM_MASTER_KEY environment variables are required"
        )
        return False

    payload = {"keys": [api_key]}

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.post(
            f"{litellm_url}/key/delete", headers=headers, json=payload, timeout=30
        )
        response.raise_for_status()

        data = response.json()
        deleted_keys = data.get("deleted_keys", [])

        if api_key in deleted_keys:
            logger.info(f"Successfully deleted LiteLLM key: {api_key[:20]}...")
            return True
        else:
            logger.warning(f"Key not found in deleted keys: {api_key[:20]}...")
            return False

    except requests.RequestException as e:
        logger.error(f"Failed to delete LiteLLM key {api_key[:20]}...: {e}")
        return False


def get_key_info(api_key: str) -> Optional[Dict]:
    """Get key-specific information from /key/info endpoint"""
    litellm_url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")

    if not litellm_url or not master_key:
        logger.error(
            "LITELLM_URL and LITELLM_MASTER_KEY environment variables are required"
        )
        return None

    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }

    try:
        response = requests.get(
            f"{litellm_url}/key/info",
            headers=headers,
            params={"key": api_key},
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        logger.debug(f"Retrieved key info for {api_key[:20]}...")
        return data

    except requests.RequestException as e:
        logger.error(f"Failed to get key info for {api_key[:20]}...: {e}")
        return None


def get_key_stats(api_key: str) -> Optional[Dict]:
    """Get comprehensive statistics combining key info and user activity"""
    # Get key-specific information
    key_info = get_key_info(api_key)

    # Get user activity data
    user_activity = get_user_daily_activity(api_key)

    # Combine both datasets
    if key_info is None and user_activity is None:
        logger.warning(
            f"Failed to retrieve both key info and user activity for {api_key[:20]}..."
        )
        return None

    combined_stats = {
        "key_info": key_info,
        "user_activity": user_activity,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    logger.debug(f"Retrieved comprehensive stats for key {api_key[:20]}...")
    return combined_stats


def save_key_stats(eval_dir: Path, target: str, config_hash: str, stats: Dict) -> None:
    """Save key statistics to eval_dir/metadata/{target}/{config_hash}.json"""
    metadata_dir = eval_dir / "metadata" / target
    metadata_dir.mkdir(parents=True, exist_ok=True)

    stats_file = metadata_dir / f"{config_hash}.json"

    # Prepare stats data with timestamp
    stats_data = {
        "target": target,
        "config_hash": config_hash,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        **stats,  # Include all stats from LiteLLM
    }

    try:
        with open(stats_file, "w") as f:
            json.dump(stats_data, f, indent=2)

        logger.info(f"Saved LiteLLM stats to: {stats_file}")

    except Exception as e:
        logger.error(f"Failed to save LiteLLM stats to {stats_file}: {e}")


def load_key_stats(eval_dir: Path, target: str, config_hash: str) -> Optional[Dict]:
    """Load previously saved key statistics from metadata file"""
    metadata_dir = eval_dir / "metadata" / target
    stats_file = metadata_dir / f"{config_hash}.json"

    try:
        if not stats_file.exists():
            logger.debug(f"Stats file not found: {stats_file}")
            return None

        with open(stats_file, "r") as f:
            stats_data = json.load(f)

        logger.debug(f"Loaded LiteLLM stats from: {stats_file}")
        return stats_data

    except Exception as e:
        logger.error(f"Failed to load LiteLLM stats from {stats_file}: {e}")
        return None
