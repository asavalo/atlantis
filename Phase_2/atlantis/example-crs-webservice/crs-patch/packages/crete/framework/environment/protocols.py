from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from crete.atoms.detection import Detection
from crete.framework.environment.contexts import EnvironmentContext

if TYPE_CHECKING:
    from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


class EnvironmentProtocol(Protocol):
    """
    Defines the protocol for an environment that interacts with the challenge project (CP).

    The environment is responsible for managing the state of the CP, including restoring
    to a specific state, building the project, applying patches, running proof-of-vulnerability
    (POV) tests, and executing the test suite.

    Methods:
        restore: Restores the CP to a specific state.
        build: Builds the CP.
        patch: Applies a patch to the CP.
        run_pov: Runs a proof-of-vulnerability test.
        run_tests: Executes the CP's test suite.
        shell: Executes a command in the CP's shell.

    Each method returns a tuple of (stdout, stderr) as strings, representing the output
    of the operation.

    Attributes:
        source_directory: Path to the source directory of the CP.
    """

    pool: "EnvironmentPoolProtocol"

    def __init__(
        self,
        pool: "EnvironmentPoolProtocol",
    ) -> None:
        self.pool = pool

    def restore(self, context: EnvironmentContext) -> tuple[str, str]: ...

    def build(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]: ...

    def patch(
        self,
        context: EnvironmentContext,
        patch: Path | bytes,
        env: dict[str, str] = {},
    ) -> tuple[str, str]: ...

    def check_build(self, context: EnvironmentContext) -> tuple[str, str]: ...

    def run_pov(
        self, context: EnvironmentContext, detection: Detection
    ) -> tuple[str, str]: ...

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]: ...

    def shell(self, context: EnvironmentContext, command: str) -> tuple[str, str]: ...

    def execute(
        self,
        context: EnvironmentContext,
        command: str,
        env: dict[str, str] = {},
    ) -> tuple[str, str]: ...

    def clone(
        self, context: EnvironmentContext, project_name: str
    ) -> "EnvironmentProtocol": ...
