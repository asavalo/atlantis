from pathlib import Path

from crete.atoms.detection import Detection
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.protocols import EnvironmentProtocol


class MockEnvironment(EnvironmentProtocol):
    def restore(self, context: EnvironmentContext) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def build(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def patch(
        self,
        context: EnvironmentContext,
        patch: Path | bytes,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def check_build(
        self,
        context: EnvironmentContext,
    ) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def run_pov(
        self, context: EnvironmentContext, detection: Detection
    ) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def shell(self, context: EnvironmentContext, command: str) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def execute(
        self,
        context: EnvironmentContext,
        command: str,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        return "", ""  # No-op, nothing to

    def clone(
        self, context: EnvironmentContext, project_name: str
    ) -> "EnvironmentProtocol":
        return self
