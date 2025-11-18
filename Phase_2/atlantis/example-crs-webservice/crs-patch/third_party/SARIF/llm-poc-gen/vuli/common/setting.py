import base64
import json
import logging
import tempfile
import threading
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel
from vuli.common.decorators import synchronized
from vuli.common.singleton import Singleton
from vuli.struct import CodeLocation, CodePoint


class Setting(metaclass=Singleton):
    mode: str = None

    # Joern
    joern_timeout: int = 30

    def __init__(self):
        self.agent_path: Optional[Path] = None
        self.blackboard_path: Optional[Path] = None
        self.calltree_db_path: Optional[Path] = None
        self.cpg_path: Optional[Path] = None
        self.jazzer_path: Optional[Path] = None
        self.joern_dir: Optional[Path] = None
        self.joern_cli_path: Optional[Path] = None
        self.joern_javasrc_path: Optional[Path] = None
        self.mode: str = ""
        self.output_dir: Optional[Path] = None
        self.query_path: Optional[Path] = None
        self.semantic_dir: Optional[Path] = None
        self.root_dir: Optional[Path] = None
        self.tmp_dir: Path = Path(tempfile.gettempdir())
        self.sarif_path: Optional[Path] = None
        self.cp_root: Optional[Path] = None
        self.shared_dir: Path = None
        self._logger = logging.getLogger("Setting")

    def load(
        self,
        jazzer_path: Optional[Path],
        joern_dir: Path,
        output_dir: Path,
        root_dir: Path,
        dev: bool,
        sarif_path: Path,
        shared_dir: Path,
    ) -> None:
        self.jazzer_path = jazzer_path
        self.joern_dir = joern_dir
        self.output_dir = output_dir
        self.root_dir = root_dir
        self.dev = dev

        if self.joern_dir is None:
            self.joern_cli_path = Path("joern")
            self.joern_javasrc_path = Path("javasrc2cpg")
        self.joern_cli_path = self.joern_dir / "joern"
        self.joern_javasrc_path = (
            self.joern_dir / "joern-cli" / "frontends" / "javasrc2cpg" / "javasrc2cpg"
        )
        if self.output_dir.is_file():
            self.output_dir.unlink()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.blackboard_path = self.output_dir / "blackboard"
        self.calltree_db_path = self.output_dir / "calltree.db"
        self.cpg_path = self.output_dir.parent / "cpg"
        self.agent_path: Path = (
            self.root_dir / "javaagent" / "target" / "java-agent-1.0-SNAPSHOT.jar"
        )
        self.query_path = self.root_dir / "script" / "script.sc"
        self.semantic_dir = self.root_dir / "script" / "semantics"
        self.tmp_dir = self.root_dir / "temp_dir"
        self.tmp_dir.mkdir(exist_ok=True)
        self.sarif_path = sarif_path
        self.shared_dir = shared_dir
        self.cp_root = self.root_dir.parent.parent / "cp_root"
        inputs: list[str] = [
            "joern_dir",
            "joern_cli_path",
            "joern_javasrc_path",
            "query_path",
            "root_dir",
            "semantic_dir",
        ] + (["jazzer_path", "agent_path"] if jazzer_path else [])
        outputs: list[str] = ["blackboard_path", "calltree_db_path", "cpg_path"]
        invalid_inputs: list[Path] = [(x, getattr(self, x, None)) for x in inputs]
        invalid_inputs: list[Path] = [
            str(x)
            for x, value in invalid_inputs
            if (value is None) or (not isinstance(value, Path)) or (not value.exists())
        ]
        if len(invalid_inputs) > 0:
            msg: str = f"Invalid Paths: {", ".join(invalid_inputs)}"
            self._logger.error(msg)
            raise RuntimeError(msg)

        [
            self._logger.info(f"{x} is set to {self.__dict__.get(x, None)}")
            for x in sorted(inputs + outputs)
        ]


class StorageDataStatus(Enum):
    NOT_REACHED = 0
    REACHED = 1
    EXPLOITED = 2


class StoragePath(BaseModel):
    harness_id: str
    route: list[CodeLocation]
    bug_types: list[str]
    status: StorageDataStatus


class StorageSink(BaseModel):
    file_path: str
    line: int
    column: int
    bug_types: list[str]


class Storage(metaclass=Singleton):
    def __init__(self):
        self._lock: threading.Lock = threading.Lock()
        self._logger = logging.getLogger("Storage")
        self._path: Path = None
        self._seed: dict[str, set[bytes]] = {}
        self._sinks: list[StorageSink] = []
        self._paths: list[StoragePath] = []
        self._time = -1

    @synchronized("_lock")
    def add_seed(self, harness_id: str, blob: bytes) -> None:
        if self._add_seed(harness_id, {base64.b64encode(blob).decode("utf-8")}) is True:
            self._save_seed()

    @synchronized("_lock")
    def add_sink(
        self,
        file_path: str,
        line: int,
        column: int,
        bug_types: list[str],
    ) -> None:
        self._sinks.append(
            StorageSink(
                file_path=file_path,
                line=line,
                column=column,
                bug_types=bug_types,
            )
        )

    @synchronized("_lock")
    def add_path(
        self,
        harness_id: str,
        path: list[CodePoint],
        bug_types: list[str],
        status: StorageDataStatus,
    ) -> None:
        self._paths.append(
            StoragePath(
                harness_id=harness_id,
                route=[CodeLocation(x.path, x.line, x.column) for x in path],
                bug_types=bug_types,
                status=status,
            )
        )

    @synchronized("_lock")
    def clear(self) -> None:
        self._seed = {}
        self._sinks = []
        self._paths = []

    @synchronized("_lock")
    def save(self) -> None:
        def convert_enum(obj):
            if isinstance(obj, Enum):
                return obj.name

        root: dict = {
            "sinks": [sink.model_dump() for sink in self._sinks],
            "paths": [path.model_dump() for path in self._paths],
        }
        if self._time >= 0:
            root["time"] = self._time
        root.update(self._seed_to_dump())
        with self._path.open("wt") as f:
            json.dump(root, f, indent=4, default=convert_enum)

    @synchronized("_lock")
    def set_path(self, path) -> None:
        self._path = path

    def set_time(self, time: int) -> None:
        self._time = time

    def _add_seed(self, harness_id: str, blobs: set[str]) -> None:
        seeds: set[bytes] = self._seed.setdefault(harness_id, set())
        new_seeds: set[bytes] = blobs - seeds
        if len(new_seeds) == 0:
            return False
        seeds |= new_seeds
        self._logger.info(f"{len(new_seeds)} seeds are generated for {harness_id}")
        return True

    def _save_seed(self) -> None:
        with self._path.open("wt") as f:
            json.dump(self._seed_to_dump(), f, indent=4)

    def _seed_to_dump(self) -> dict:
        keys: list[str] = sorted(list(self._seed.keys()))
        return {
            "result": [
                {"harness_id": key, "blob": sorted(list(self._seed[key]))}
                for key in keys
            ]
        }
