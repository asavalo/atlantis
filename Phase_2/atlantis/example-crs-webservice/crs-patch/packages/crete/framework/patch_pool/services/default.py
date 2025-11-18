import hashlib
from pathlib import Path

from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.functions import (
    load_environment,
    save_environment,
)
from crete.framework.patch_pool.contexts import PatchPoolContext
from crete.framework.patch_pool.protocol import PatchPoolProtocol


def get_patch_name(patch: str) -> str:
    return f"Patch-{hashlib.sha256(patch.encode()).hexdigest()}"


class DefaultPatchPool(PatchPoolProtocol):
    def __init__(self, cache_directory: Path = DEFAULT_CACHE_DIRECTORY / "patches"):
        self._cache_directory = cache_directory
        self._cache_directory.mkdir(parents=True, exist_ok=True)

    def _get_patch_directory(self, patch: str) -> Path:
        return self._cache_directory / get_patch_name(patch)

    def _is_already_saved(self, patch: str) -> bool:
        return self._get_patch_directory(patch).exists()

    def save(self, context: PatchPoolContext, patch: str):
        if self._is_already_saved(patch):
            return

        directory = self._get_patch_directory(patch)
        directory.mkdir(parents=True, exist_ok=True)

        save_environment(context["pool"], context, directory)

    def load(self, context: PatchPoolContext, patch: str) -> EnvironmentProtocol | None:
        if not self._is_already_saved(patch):
            return None

        directory = self._get_patch_directory(patch)
        environment = context["pool"].use(context, "CLEAN")
        assert environment is not None
        load_environment(context["pool"], context, directory)
        return environment
