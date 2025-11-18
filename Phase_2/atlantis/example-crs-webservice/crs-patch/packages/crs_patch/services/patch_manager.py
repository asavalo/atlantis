import atexit
import threading
import shutil
import tempfile
from pathlib import Path
from uuid import UUID

from crete.commons.logging.hooks import use_logger
from crete.framework.environment.exceptions import ChallengePoVFoundError
from crete.framework.patch_pool.contexts import PatchPoolContext
from crete.framework.patch_pool.services.default import DefaultPatchPool
from crs_patch.functions import get_environment_context, init_environment_pool
from crs_patch.models import PatchRequest, SubmissionStatus
from python_aixcc_challenge.detection.models import (
    AIxCCChallengeMode,
)


class PatchManager:
    def __init__(
        self,
        project_name: str,
        challenge_mode: AIxCCChallengeMode,
        challenge_project_directory: Path,
    ):
        self.logger = use_logger("patch-manager", level="DEBUG")
        self.cache_directory = self._init_cache_directory()
        self.environment_context = get_environment_context(
            self.logger, "address", self.cache_directory
        )
        self.environment_pool = init_environment_pool(
            self.environment_context,
            project_name,
            challenge_mode,
            challenge_project_directory,
        )
        self.patch_pool_context: PatchPoolContext = {
            **self.environment_context,
            "pool": self.environment_pool,
        }
        self.patch_pool = DefaultPatchPool(cache_directory=self.cache_directory)

        self.patches: dict[str, PatchRequest] = {}
        self.lock = threading.Lock()

    def _init_cache_directory(self) -> Path:
        temp_directory = tempfile.mkdtemp()
        atexit.register(lambda: shutil.rmtree(temp_directory))
        return Path(temp_directory)

    def is_pov_blocked(self, request: PatchRequest) -> bool:
        with self.lock:
            for patch in self.patches:
                environment = self.patch_pool.load(self.patch_pool_context, patch)

                if environment is None:
                    self.environment_context["logger"].warning(
                        f"Pathced environment is not found for: {patch}"
                    )
                    continue

                try:
                    # If the POV is not found by a previous patch, the pov is blocked
                    stdout, stderr = environment.run_pov(
                        self.environment_context,
                        request.to_run_pov_detection(),
                    )
                    self.environment_context["logger"].info(
                        f"POV is blocked by patch: {patch}\nstdout: {stdout}\nstderr: {stderr}"
                    )
                    return True
                except ChallengePoVFoundError:
                    pass
            return False

    def add_patch(self, patch: str, request: PatchRequest) -> list[UUID]:
        with self.lock:
            environment = self.environment_pool.restore(self.environment_context)

            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_file.write(patch.encode("utf-8"))
                tmp_file.flush()

                try:
                    environment.patch(self.environment_context, Path(tmp_file.name))
                except Exception as e:
                    self.environment_context["logger"].error(
                        f"Failed to patch environment: {e}"
                    )
                    return []

            patched_again_pov_ids: list[UUID] = []
            for previous_request in self.patches.values():
                try:
                    environment.run_pov(
                        self.environment_context,
                        previous_request.to_run_pov_detection(),
                    )
                    self.environment_context["logger"].info(
                        f"Previous POV: {previous_request.pov_id} is blocked by new patch"
                    )
                    patched_again_pov_ids.append(previous_request.pov_id)
                except ChallengePoVFoundError:
                    pass

            self.patch_pool.save(self.patch_pool_context, patch)
            self.patches[patch] = request

            self.environment_context["logger"].info(
                f"Added patch to patch pool: {patch}"
            )

            return patched_again_pov_ids

    def remove_patch(self, pov_id: UUID, status: SubmissionStatus) -> None:
        with self.lock:
            if status != SubmissionStatus.failed:
                return

            for patch, request in list(self.patches.items()):
                if request.pov_id == pov_id:
                    del self.patches[patch]
                    self.environment_context["logger"].info(
                        f"Removed patch from patch pool: {patch}"
                    )
