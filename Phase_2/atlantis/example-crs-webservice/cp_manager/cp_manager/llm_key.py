import os
import time
import requests

from .redis_util import RedisUtil

from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()


def wait_litellm(url):
    url = f"{url}/health/liveness"
    while True:
        try:
            r = requests.get(url)
            if r.ok:
                return True
        except:
            pass


def create_llm_key(url, budget, username=""):
    wait_litellm(url)
    master_key = os.getenv("LITELLM_MASTER_KEY")
    url = f"{url}/user/new"
    headers = {
        "Authorization": f"Bearer {master_key}",
        "Content-Type": "application/json",
    }
    data = {
        "max_budget": budget,
        "user_alias": username,
    }
    while True:
        try:
            r = requests.post(url, headers=headers, json=data)
            if r.ok:
                r = r.json()
                return r["key"]
        except Exception as e:
            logger.error(f"Error creating LLM key: {e}")
            time.sleep(5)


def __get_llm_budget_rate(crs_name: str):
    assert crs_name in ["CRS_patch", "CRS_java", "CRS_multilang", "CRS_userspace"]
    rates = {}
    for name in ["CRS_patch", "CRS_java", "CRS_multilang", "CRS_userspace"]:
        rates[name] = int(os.getenv(f"LLM_budget_{name}") or 0)
    assert rates["CRS_java"] == rates["CRS_multilang"] == rates["CRS_userspace"]
    total = rates["CRS_patch"] + rates["CRS_multilang"] * 2
    return rates[crs_name] / total


URL_MAP = {
    "CRS_patch": os.getenv("LITELLM_PATCH_URL"),
    "CRS_multilang": os.getenv("LITELLM_MULTILANG_URL"),
    "CRS_java": os.getenv("LITELLM_USER_JAVA_URL"),
    "CRS_userspace": os.getenv("LITELLM_USER_JAVA_URL"),
}


def __get_litellm_url(crs_name):
    return URL_MAP[crs_name]


def __create_llm_key_per_crs(redis_util, crs_name, total_budget: int):
    rate = __get_llm_budget_rate(crs_name)
    budget = int(total_budget * rate)
    url = __get_litellm_url(crs_name)
    username = crs_name + "_" + str(os.getenv("TASK_ID"))
    key = create_llm_key(url, budget, username)
    logger.info(f"Create LLM key for {url}, {crs_name}, {budget} => {key}, {username}")
    os.environ[f"LITELLM_KEY_{crs_name}"] = key
    redis_util.set_llm_key(crs_name, key)
    return key


def create_crs_patch_llm_key(redis_util, total_budget: int):
    return __create_llm_key_per_crs(redis_util, "CRS_patch", total_budget)


def create_crs_multilang_llm_key(redis_util, total_budget: int):
    return __create_llm_key_per_crs(redis_util, "CRS_multilang", total_budget)


def create_crs_java_llm_key(redis_util, total_budget: int):
    return __create_llm_key_per_crs(redis_util, "CRS_java", total_budget)


def create_crs_userspace_llm_key(redis_util, total_budget: int):
    return __create_llm_key_per_crs(redis_util, "CRS_userspace", total_budget)
