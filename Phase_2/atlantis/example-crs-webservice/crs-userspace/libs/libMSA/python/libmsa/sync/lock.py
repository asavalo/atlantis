from typing import Any, Callable, TypeVar

from kazoo.client import KazooClient
from kazoo.recipe.lock import Lock

R = TypeVar("R")


class LockedFunctionRunner:
    def __init__(self, zk_hosts: str, lock_path: str) -> None:
        self.zk = KazooClient(hosts=zk_hosts)
        self.lock_path = lock_path
        self.zk.start()
        self.lock = Lock(self.zk, self.lock_path)

    def run_with_lock(self, func: Callable[..., R], *args: Any, **kwargs: Any) -> R:
        with self.lock:
            result = func(*args, **kwargs)
            return result

    def close(self) -> None:
        self.zk.stop()
