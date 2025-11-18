from typing import Protocol

from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.patch_pool.contexts import PatchPoolContext


class PatchPoolProtocol(Protocol):
    def save(self, context: PatchPoolContext, patch: str): ...

    def load(
        self, context: PatchPoolContext, patch: str
    ) -> EnvironmentProtocol | None: ...
