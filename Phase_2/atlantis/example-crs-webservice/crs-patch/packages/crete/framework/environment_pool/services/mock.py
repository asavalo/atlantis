from pathlib import Path

from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment.services.mock import MockEnvironment
from crete.framework.environment_pool.models import EnvironmentType
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


class MockEnvironmentPool(EnvironmentPoolProtocol):
    def __init__(
        self,
        challenge_project_directory: Path,
        detection_toml_file: Path,
    ):
        super().__init__(
            source_directory=challenge_project_directory,
            project_directory=challenge_project_directory,
            out_directory=challenge_project_directory,
            work_directory=challenge_project_directory,
        )

        self._mock_environment = MockEnvironment(self)

    def use(
        self, context: EnvironmentContext, type: EnvironmentType
    ) -> EnvironmentProtocol | None:
        return self._mock_environment

    def restore(self, context: EnvironmentContext) -> EnvironmentProtocol:
        return self._mock_environment

    def internal_test_exists(self) -> bool:
        return True

    def internal_test_script_path(self) -> Path:
        # NOTE: This is a mock environment so I'm just putting test.sh here.
        # If this is needed in future, check OssFuzzEnvironmentPool's implementation.
        return Path(self.project_directory / "test.sh")
