import tempfile
from pathlib import Path

from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.path.globals import OSS_FUZZ_HELPER_FILE

from crete.atoms.detection import Detection
from crete.atoms.path import PACKAGES_DIRECTORY
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import ChallengePoVFoundError
from crete.framework.environment.functions import rsync_directory
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


class CallTraceOssFuzzEnvironment(EnvironmentProtocol):
    def __init__(
        self,
        pool: EnvironmentPoolProtocol,
        environment: EnvironmentProtocol,
        challenge_project_yaml: AIxCCChallengeProjectYaml,
        challenge_project_detection: AIxCCChallengeProjectDetection,
    ):
        super().__init__(pool=pool)
        self.environment = environment
        self._challenge_project_yaml = challenge_project_yaml
        self._challenge_project_detection = challenge_project_detection

    def restore(self, context: EnvironmentContext) -> tuple[str, str]:
        return self.environment.restore(context)

    def build(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        match self._challenge_project_yaml.language:
            case "c" | "c++" | "cpp":
                return self._build_for_c(context, env)
            case "jvm":
                return self._build_for_jvm(context, env)

    def _build_for_c(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        self._install_c_instrumenter_artifacts()
        return self.environment.build(
            context,
            env={
                "CC": "/work/function_call_logger/clang-wrapper",
                "CXX": "/work/function_call_logger/clang-wrapper++",
                **env,
            },
        )

    def patch(
        self,
        context: EnvironmentContext,
        patch: Path | bytes,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        return self.environment.patch(context, patch, env)

    def check_build(self, context: EnvironmentContext) -> tuple[str, str]:
        return self.environment.check_build(context)

    def run_pov(
        self, context: EnvironmentContext, detection: Detection
    ) -> tuple[str, str]:
        assert len(detection.blobs) > 0, "At least one blob is required"
        try:
            with tempfile.NamedTemporaryFile(delete_on_close=False) as blob_file:
                blob_file.write(detection.blobs[0].blob)
                blob_file.close()

                return run_command(
                    command=(
                        f"{OSS_FUZZ_HELPER_FILE} reproduce {self._challenge_project_detection.project_name} {detection.blobs[0].harness_name} {blob_file.name}",
                        self.pool.source_directory,
                    ),
                    timeout=600,
                )
        except CommandInteractionError as e:
            raise ChallengePoVFoundError(
                stdout=e.stdout,
                stderr=e.stderr,
            )

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self.environment.run_tests(context, env)

    def shell(self, context: EnvironmentContext, command: str) -> tuple[str, str]:
        return self.environment.shell(context, command)

    def _install_c_instrumenter_artifacts(self):
        llvm_pass_artifacts_path = (
            PACKAGES_DIRECTORY / "cpp_function_call_logging/build"
        )
        rsync_directory(
            llvm_pass_artifacts_path,
            self.pool.work_directory / "function_call_logger",
        )
        rsync_directory(
            llvm_pass_artifacts_path,
            self.pool.out_directory / "function_call_logger",
        )

    def _build_for_jvm(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        self._install_jvm_instrumeter_artifacts()
        build_stdout, build_stderr = self.environment.build(context, env)

        shell_stdout, shell_stderr = self.environment.shell(
            context,
            (
                "chmod 755 /work/jvm_method_call_logging/instrument.sh;"
                "/work/jvm_method_call_logging/instrument.sh"
            ),
        )

        return build_stdout + shell_stdout, build_stderr + shell_stderr

    def _install_jvm_instrumeter_artifacts(self):
        instrumenter_original_directory = PACKAGES_DIRECTORY / "jvm_method_call_logging"
        rsync_directory(
            instrumenter_original_directory,
            self.pool.work_directory / "jvm_method_call_logging",
        )

    def clone(
        self, context: EnvironmentContext, project_name: str
    ) -> EnvironmentProtocol:
        return self.environment.clone(context, project_name)

    def execute(
        self, context: EnvironmentContext, command: str, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self.environment.execute(context, command, env)
