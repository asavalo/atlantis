import logging
import threading
from enum import Enum
from typing import Optional

from pydantic import BaseModel
from vuli.common.decorators import synchronized
from vuli.common.singleton import Singleton
from vuli.joern import Joern
from vuli.struct import Sanitizer


class Status(Enum):
    UNKNOWN = 0
    UNEXPLOITABLE = 1
    MAY_UNREACHABLE = 2
    MAY_REACHABLE = 3


class Origin(Enum):
    FROM_INSIDE = 0
    FROM_CRS = 1
    FROM_DELTA = 2
    FROM_SARIF = 3


class SinkProperty(BaseModel):
    bug_types: set[str]
    origins: set[Origin]
    status: Status = Status.UNKNOWN

    def __str__(self) -> str:
        return f"(bug_types:{",".join(self.bug_types)}, origins:{",".join([x.name for x in self.origins])}, status:{self.status.name})"


class SinkManager(metaclass=Singleton):
    def __init__(self):
        self._logger = logging.getLogger("SinkManager")
        self._lock = threading.Lock()
        self._table: dict[int, SinkProperty] = {}

    @synchronized("_lock")
    def add_batch(self, sinks: dict[int, SinkProperty]) -> None:
        for id, property in sinks.items():
            self._add((id, property))

    @synchronized("_lock")
    def add(self, sink: tuple[int, SinkProperty]) -> None:
        self._add(sink)

    @synchronized("_lock")
    def clear(self) -> None:
        self._table.clear()

    @synchronized("_lock")
    def get_bug_types(self, id: int) -> set[str]:
        if id not in self._table:
            self._logger.warning(f"Sink Not Found [id={id}]")
            return {}
        return self._table[id].bug_types

    @synchronized("_lock")
    def get_origin(self, id: int) -> Optional[Origin]:
        if id not in self._table:
            self._logger.warning(f"Sink Not Found [id={id}]")
            return None
        origins = self._table[id].origins
        if len(origins) == 0:
            self._logger.warning(
                f"Origin Not Found [id={id}, property={self._table[id]}]"
            )
            return None
        return max(origins, key=lambda x: x.value)

    @synchronized("_lock")
    def get_status(self, id: int) -> Status:
        if id not in self._table:
            return Status.UNKNOWN
        return self._table[id].status

    @synchronized("_lock")
    def get(self) -> dict[int, SinkProperty]:
        return self._table

    @synchronized("_lock")
    def update_status(self, id: int, status: Status) -> None:
        if id not in self._table:
            self._logger.warning(f"Sink Not Found [id={id}]")
            return
        self._table[id].status = status

    def _add(self, sink: tuple[int, SinkProperty]) -> None:
        id, property = sink
        if id not in self._table:
            self._table[id] = property
            self._logger.info(f"Sink Added[id={id},property={property}]")
            return
        self._table[id].bug_types |= property.bug_types
        self._table[id].origins |= property.origins
        self._logger.info(f"Sink may updated[id={id},property={self._table[id]}]")


logger = logging.getLogger("vuli")


class Scanner:
    def __init__(self):
        self._logger = logging.getLogger("Scanner")

    def scan(self, sanitizers: list[Sanitizer]):
        joern_queries: list[tuple[str, str]] = [
            (x.name, Joern().get_sink_name(x.name)) for x in sanitizers
        ]
        joern_result: list[tuple[str, set[int]]] = [
            (
                name,
                set(
                    Joern().run_query(
                        f"""
{sink_name}
    .whereNot(_.method.filename(".*/src/test/.*"))
    .whereNot(_.method.filenameExact("<empty>"))
    .filterNot{{
        case x: CfgNode => check_constant(x)
        case _ => false
    }}
    .id.l
""",
                        600,
                    )
                ),
            )
            for name, sink_name in joern_queries
        ]
        result: dict[int, SinkProperty] = {
            sink: SinkProperty(
                bug_types={name}, origins={Origin.FROM_INSIDE}, status=Status.UNKNOWN
            )
            for name, sinks in joern_result
            for sink in sinks
        }
        SinkManager().add_batch(result)
