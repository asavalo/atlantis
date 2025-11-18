"""
THIS IS ONLY FOR TESTING
"""

import os
import requests
import time
from loguru import logger


def wait_litellm():
    url = os.getenv("LITELLM_URL")
    url = f"{url}/health/liveness"
    while True:
        try:
            r = requests.get(url)
            if r.ok:
                return True
        except:
            pass


def delete_budget(crs_name: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/budget/delete"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "id": f"budget_{crs_name}",
    }
    r = requests.post(url, headers=headers, json=data)
    if r.ok:
        return r.json()
    return None


def create_budget(crs_name: str, budget: float):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/budget/new"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "budget_id": f"budget_{crs_name}",
        "max_budget": budget,
    }
    r = requests.post(url, headers=headers, json=data)
    if r.ok:
        return r.json()
    return None


def info_llm_key(key: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/key/info"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "key": key,
    }
    r = requests.get(url, headers=headers, params=data)
    if r.ok:
        return r.json()
    return None


def info_budget(crs_name: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/budget/info"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "budgets": [f"budget_{crs_name}"],
    }
    r = requests.post(url, headers=headers, json=data)
    if r.ok:
        return r.json()
    return None


def create_llm_key(crs_name: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/key/generate"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "user_id": f"user_{crs_name}",
    }
    for _ in range(10):
        try:
            r = requests.post(url, headers=headers, json=data)
            if r.ok:
                r = r.json()
                return r["key"]
        except Exception as e:
            logger.error(f"Error creating LLM key: {e}")
            time.sleep(5)
    return "ERROR_LLM_KEY"


def spend_logs(api_key: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/spend/logs"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "api_key": api_key,
    }
    r = requests.get(url, headers=headers, params=data)
    if r.ok:
        return r.json()
    return None


def create_user(crs_name: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/user/new"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "user_id": f"user_{crs_name}",
    }
    r = requests.post(url, headers=headers, json=data)
    if r.ok:
        return r.json()
    return r


def info_user(crs_name: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/user/info"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "user_id": f"user_{crs_name}",
    }
    r = requests.get(url, headers=headers, params=data)
    if r.ok:
        return r.json()
    return None


def delete_user(crs_name: str):
    wait_litellm()
    url = os.getenv("LITELLM_URL")
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/user/delete"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "user_ids": [f"user_{crs_name}"],
    }
    r = requests.post(url, headers=headers, json=data)
    if r.ok:
        return r.json()
    return None
