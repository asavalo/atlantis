import os
import time
import requests
import logging
import redis
import redis_lock
from loguru import logger

from my_crs.crs_manager.log_config import setup_logger

setup_logger()

logging.getLogger("redis_lock").setLevel(logging.WARNING)


def connect_redis():
    url = redis_endpoint = os.getenv("CRS_REDIS_ENDPOINT")
    if url == None:
        os.system(
            f"redis-server --port 22222 --bind localhost --daemonize yes > /dev/null"
        )
        url = "redis://localhost:22222"
        os.environ["CRS_REDIS_ENDPOINT"] = url
    redis_client = redis.from_url(url, decode_responses=True)
    return redis_client


class BudgetDB:
    def __init__(self, name: str):
        self.name = name
        self.budgets = {}
        self.returned_budgets = 0
        self.returned_cnt = 0

    def get_budget(self, task_id: str) -> int:
        if task_id not in self.budgets:
            return 0
        return self.budgets[task_id]

    def set_budget(self, task_id: str, budget: int):
        self.budgets[task_id] = budget

    def deposit_returned_budget(self, budget: int):
        self.returned_budgets += budget
        self.returned_cnt += 1

    def withdraw_returned_budget(self):
        if self.returned_cnt == 0:
            return 0
        budget = int(self.returned_budgets / self.returned_cnt)
        self.returned_budgets -= budget
        self.returned_cnt -= 1
        return budget


class RedisBudgetDB:
    def __init__(self, name: str):
        self.name = name
        self.redis = connect_redis()

    def __lock(self):
        return redis_lock.Lock(
            self.redis,
            name=f"lock_{self.name}_budget",
            expire=10,
            auto_renewal=True,
        )

    def __get_budget_key(self, task_id: str) -> str:
        return f"{self.name}_budget_{task_id}"

    def __get_returned_budget_key(self) -> str:
        return f"{self.name}_returned_budget"

    def __get_returned_cnt_key(self) -> str:
        return f"{self.name}_returned_cnt"

    def reset_budget(self):
        with self.__lock():
            self.redis.delete(self.__get_budget_key("*"))
            self.redis.delete(self.__get_returned_budget_key())
            self.redis.delete(self.__get_returned_cnt_key())

    def get_budget(self, task_id: str) -> int:
        with self.__lock():
            key = self.__get_budget_key(task_id)
            return int(self.redis.get(key) or 0)

    def set_budget(self, task_id: str, budget: int):
        with self.__lock():
            key = self.__get_budget_key(task_id)
            self.redis.set(key, budget)

    def __get_returned_budget(self) -> int:
        return int(self.redis.get(self.__get_returned_budget_key()) or 0)

    def __set_returned_budget(self, budget: int):
        self.redis.set(self.__get_returned_budget_key(), budget)

    def __get_returned_cnt(self) -> int:
        return int(self.redis.get(self.__get_returned_cnt_key()) or 0)

    def __set_returned_cnt(self, cnt: int):
        self.redis.set(self.__get_returned_cnt_key(), cnt)

    def deposit_returned_budget(self, budget: int):
        with self.__lock():
            returned_budget = self.__get_returned_budget()
            returned_budget += budget
            self.__set_returned_budget(returned_budget)

            returned_cnt = self.__get_returned_cnt()
            self.__set_returned_cnt(returned_cnt + 1)

    def withdraw_returned_budget(self):
        with self.__lock():
            returned_cnt = self.__get_returned_cnt()
            if returned_cnt == 0:
                return 0
            returned_budget = self.__get_returned_budget()
            budget = int(returned_budget / returned_cnt)
            returned_budget -= budget
            self.__set_returned_budget(returned_budget)
            self.__set_returned_cnt(returned_cnt - 1)
            return budget


class BudgetAllocator:
    def __init__(self, db, total_budget: int, max_task_cnt: int):
        self.db = db
        self.total_budget = total_budget
        self.max_task_cnt = max_task_cnt
        assert self.total_budget > 0
        assert self.max_task_cnt > 0
        self.info(
            f"Total budget: {self.total_budget}, max task cnt: {self.max_task_cnt}"
        )

    def info(self, msg):
        logger.info(f"[BudgetAllocator][{self.db.name}] {msg}")

    def return_budget(self, task_id: str, spend: int):
        budget = self.db.get_budget(task_id)
        budget -= spend
        self.info(
            f"Return budget for task {task_id} spend {spend}, returned {budget}"
        )
        self.db.deposit_returned_budget(budget)

    def allocate_budget(self, task_id: str) -> int:
        budget = self.db.get_budget(task_id)
        if budget > 0:
            return budget
        basic = int(self.total_budget / self.max_task_cnt)
        from_returned = self.db.withdraw_returned_budget()
        budget = basic + from_returned
        self.info(
            f"Allocate budget for task {task_id}, basic {basic}, from_returned {from_returned}, total {budget}"
        )
        self.db.set_budget(task_id, budget)
        return budget

    def reset_budget(self):
        self.db.reset_budget()


def init_llm_allocator():
    db = RedisBudgetDB("LLM")
    total_budget = int(os.getenv("TOTAL_LLM_BUDGET") or 1000)
    max_task_cnt = int(os.getenv("MAX_TASK_CNT") or 10)
    return BudgetAllocator(
        db, total_budget=total_budget, max_task_cnt=max_task_cnt
    )


def allocate_llm_budget(task_id: str):
    return init_llm_allocator().allocate_budget(task_id)


def return_llm_budget(task_id: str, spend: int):
    return init_llm_allocator().return_budget(task_id, int(spend))


def init_vcpu_allocator():
    db = RedisBudgetDB("VCPU")
    total_budget = int(os.getenv("TOTAL_VCPU") or 1000)
    max_task_cnt = int(os.getenv("MAX_TASK_CNT") or 10)
    return BudgetAllocator(
        db, total_budget=total_budget, max_task_cnt=max_task_cnt
    )


def allocate_vcpu_budget(task_id: str):
    return init_vcpu_allocator().allocate_budget(task_id)


def get_vcpu_basic_budget():
    allocator = init_vcpu_allocator()
    return int(allocator.total_budget / allocator.max_task_cnt)


def return_vcpu_budget(task_id: str, spend: int):
    return init_vcpu_allocator().return_budget(task_id, spend)

def return_all_budget(task_id: str):
    llm = allocate_llm_budget(task_id)
    vcpu = allocate_vcpu_budget(task_id)
    return_vcpu_budget(task_id, 0)
    return_llm_budget(task_id, 0)


def reset_budgets():
    init_llm_allocator().reset_budget()
    init_vcpu_allocator().reset_budget()


def wait_litellm(url):
    url = f"{url}/health/liveness"
    while True:
        try:
            r = requests.get(url)
            if r.ok:
                return True
        except:
            pass


def get_llm_spend(url: str, key: str) -> float:
    wait_litellm(url)
    url = f"{url}/key/info"
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    while True:
        try:
            r = requests.get(url, headers=headers)
            if r.ok:
                return r.json()["info"]["spend"]
        except:
            pass
        time.sleep(1)


if __name__ == "__main__":
    db = BudgetDB("llm")
    allocator = BudgetAllocator(db, total_budget=10000, max_task_cnt=30)

    total_spent = 0
    remain = 0
    for task in range(30):
        task_id = str(task)
        budget = allocator.allocate_budget(task_id)
        print(f"Task {task_id} allocated {budget}")
        spent = budget * 0.8
        remain = budget - spent
        allocator.return_budget(task_id, spent)
        print(f"Task {task_id} spent {spent} return {remain}")
        total_spent += spent

    print(f"Total spent: {total_spent}")
    print(f"Total: {total_spent + remain}")
