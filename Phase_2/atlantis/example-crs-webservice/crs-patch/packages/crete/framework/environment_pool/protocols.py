from pathlib import Path
from typing import Protocol

from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.models import EnvironmentType


class EnvironmentPoolProtocol(Protocol):
    source_directory: Path
    project_directory: Path
    out_directory: Path
    work_directory: Path

    def __init__(
        self,
        source_directory: Path,
        project_directory: Path,
        out_directory: Path,
        work_directory: Path,
    ):
        self.source_directory = source_directory
        self.project_directory = project_directory
        self.out_directory = out_directory
        self.work_directory = work_directory

    def restore(
        self,
        context: EnvironmentContext,
    ) -> EnvironmentProtocol:
        environment = self.use(context, "CLEAN")
        assert environment is not None
        return environment

    def use(
        self,
        context: EnvironmentContext,
        type: EnvironmentType,
    ) -> EnvironmentProtocol | None: ...

    def internal_test_exists(self) -> bool: ...

    def internal_test_script_path(self) -> Path: ...
