import re
import tempfile
from pathlib import Path

from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.flag.globals import (
    OSS_FUZZ_DEFAULT_CFLAGS,
    OSS_FUZZ_DEFAULT_CXXFLAGS,
)
from python_oss_fuzz.path.globals import OSS_FUZZ_HELPER_FILE

from crete.atoms.detection import Detection
from crete.commons.interaction.exceptions import CommandInteractionError, TimeoutExpired
from crete.commons.interaction.functions import run_command
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import ChallengePoVFoundError
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


def _remove_sanitizer_flags(flags: str) -> str:
    """
    By using the regex, remove "-fsanitize"-related strings.
    """
    sanitizer_pattern = r"-fsanitize[^\s]+"
    new_flags = re.sub(sanitizer_pattern, "", flags)

    return new_flags


class ValgrindOssFuzzEnvironment(EnvironmentProtocol):
    def __init__(
        self,
        pool: EnvironmentPoolProtocol,
        environment: EnvironmentProtocol,
        challenge_project_yaml: AIxCCChallengeProjectYaml,
        challenge_project_detection: AIxCCChallengeProjectDetection,
    ):
        super().__init__(
            pool=pool,
        )
        self._environment = environment
        self._challenge_project_yaml = challenge_project_yaml
        self._challenge_project_detection = challenge_project_detection

    def restore(self, context: EnvironmentContext) -> tuple[str, str]:
        return self._environment.restore(context)

    def build(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        match self._challenge_project_yaml.language:
            case "c" | "c++" | "cpp":
                return self._build_for_c(context, env)

            case "jvm":
                raise NotImplementedError("JVM is not supported yet.")

    def _build_for_c(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        # NOTE: **env should come after the ccache environment variables,
        # as we want to prioritize flags defined in higher level classes.
        env = {
            "CFLAGS": _remove_sanitizer_flags(OSS_FUZZ_DEFAULT_CFLAGS) + " -O0 -g ",
            "CXXFLAGS": _remove_sanitizer_flags(OSS_FUZZ_DEFAULT_CXXFLAGS) + " -O0 -g ",
            # Further disable the sanitizer-related flags. These are forcifully added by `compile` script during the `build_fuzzer` command.
            # They're defined in `infra/base-images/base-builder/Dockerfile`
            "SANITIZER_FLAGS_memory": "",
            "SANITIZER_FLAGS_address": "",
            "SANITIZER_FLAGS_undefined": "",
            "SANITIZER_FLAGS_undefined_aarch64": "",
            **env,
        }
        return self._environment.build(context, env)

    def patch(
        self,
        context: EnvironmentContext,
        patch: Path | bytes,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        return self._environment.patch(context, patch, env)

    def check_build(self, context: EnvironmentContext) -> tuple[str, str]:
        return self._environment.check_build(context)

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self._environment.run_tests(context, env)

    def shell(self, context: EnvironmentContext, command: str) -> tuple[str, str]:
        return self._environment.shell(context, command)

    def execute(
        self, context: EnvironmentContext, command: str, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self._environment.execute(context, command, env)

    def clone(
        self, context: EnvironmentContext, project_name: str
    ) -> EnvironmentProtocol:
        return self._environment.clone(context, project_name)

    def run_pov(
        self, context: EnvironmentContext, detection: Detection
    ) -> tuple[str, str]:
        assert len(detection.blobs) > 0, "At least one blob is required"

        stdout, stderr, success = self._run_pov(
            context, detection.blobs[0].blob, detection.blobs[0].harness_name
        )
        if success:
            return stdout, stderr
        else:
            raise ChallengePoVFoundError(
                stdout=stdout.encode(errors="ignore"),
                stderr=stderr.encode(errors="ignore"),
            )

    def _run_pov(
        self, context: EnvironmentContext, blob: bytes, harness_name: str
    ) -> tuple[str, str, bool]:
        # This is a workaround to use vcrpy to record the response from oss-fuzz
        try:
            with tempfile.NamedTemporaryFile(delete_on_close=False) as blob_file:
                blob_file.write(blob)
                blob_file.close()

                return (
                    # Use the OSS-Fuzz's valgrind support (i.e., "--valgrind" option).
                    *run_command(
                        command=(
                            f"{OSS_FUZZ_HELPER_FILE} reproduce --valgrind {self._challenge_project_detection.project_name} {harness_name} {blob_file.name}",
                            self.pool.source_directory,
                        ),
                        timeout=30,
                    ),
                    True,
                )
        except CommandInteractionError as e:
            return (
                e.stdout.decode(errors="ignore"),
                e.stderr.decode(errors="ignore"),
                False,
            )
        except TimeoutExpired as e:
            raise e
