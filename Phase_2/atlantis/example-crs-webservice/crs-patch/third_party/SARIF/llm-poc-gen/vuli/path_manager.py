import logging
import pickle
import threading
from enum import Enum
from typing import Optional

from vuli import scan
from vuli.common.decorators import synchronized
from vuli.common.singleton import Singleton
from vuli.struct import VulInfo


class Status(Enum):
    UNKNOWN = 0
    ANALYZING = 1
    MAY_UNREACHABLE = 2
    REACHABLE = 3
    EXPLOITABLE = 4


class PathManager(metaclass=Singleton):
    def __init__(self):
        self._logger = logging.getLogger("PathManager")
        self._lock = threading.Lock()
        self._key_counter: dict[str, int] = {}
        self._table: dict[bytes, Status] = {}
        self._queue: list[VulInfo] = []

    @synchronized("_lock")
    def add(self, path: VulInfo) -> None:
        self._add(path)

    @synchronized("_lock")
    def add_batch(self, paths: list[VulInfo]) -> None:
        for path in paths:
            self._add(path)

    @synchronized("_lock")
    def get_status(self, path: VulInfo) -> Status:
        serialized: bytes = pickle.dumps(path)
        return self._table.get(serialized, Status.UNKNOWN)

    @synchronized("_lock")
    def clear(self) -> None:
        self._key_counter = {}
        self._table = {}
        self._queue = []

    @synchronized("_lock")
    def get(self) -> Optional[VulInfo]:
        def to_comparable(path: VulInfo, key_priority: list[int]) -> tuple[int, int]:
            origin: Optional[scan.Origin] = scan.SinkManager().get_origin(path.sink_id)
            if origin is None:
                origin = scan.Origin.FROM_INSIDE
            try:
                harness_idx: int = key_priority.index(path.harness_id)
            except ValueError:
                harness_idx: int = 0
            return (origin.value, harness_idx)

        if len(self._queue) == 0:
            return None
        key_priority: list[int] = list(
            reversed(
                sorted(
                    list(self._key_counter.keys()),
                    key=lambda x: self._key_counter.get(x, 0),
                )
            )
        )
        pick: tuple[int, int, int] = to_comparable(self._queue[0], key_priority) + (0,)
        if pick[0] != scan.Origin.FROM_SARIF or pick[1] != len(key_priority) - 1:
            for i in range(1, len(self._queue)):
                compare: tuple[int, int] = to_comparable(self._queue[i], key_priority)
                if (
                    compare[0] == scan.Origin.FROM_SARIF
                    and compare[1] == len(key_priority) - 1
                ):
                    pick = compare + (i,)
                    break
                if compare[0] > pick[0]:
                    pick = compare + (i,)
                    continue
                if compare[0] == pick[0]:
                    if compare[1] > pick[1]:
                        pick = compare + (i,)
                        continue
        result: VulInfo = self._queue[pick[2]]
        del self._queue[pick[2]]
        self._key_counter[result.harness_id] += 1
        return result

    @synchronized("_lock")
    def update(self, path: VulInfo, status: Status) -> None:
        serialized: bytes = pickle.dumps(path)
        if serialized not in self._table:
            self._logger.warning(f"Path Not Found to Update [path={path}]")
            return
        self._table[serialized] = status
        self._logger.info(f"Path status is updated to [{status.name}]")

    def _add(self, path: VulInfo) -> None:
        serialized: bytes = pickle.dumps(path)
        if serialized in self._table:
            self._logger.warning(f"Path ignored [path={path}]")
            return
        self._table[serialized] = Status.UNKNOWN
        self._queue.append(path)
        if path.harness_id not in self._key_counter:
            self._key_counter[path.harness_id] = 0
        self._logger.info(f"Path updated[path={path}]")
