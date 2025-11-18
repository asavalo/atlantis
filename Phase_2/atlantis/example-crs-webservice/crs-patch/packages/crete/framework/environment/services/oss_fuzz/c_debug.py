from pathlib import Path

from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.flag.globals import (
    OSS_FUZZ_DEFAULT_CFLAGS,
    OSS_FUZZ_DEFAULT_CXXFLAGS,
)

from crete.atoms.detection import Detection
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


class CDebugOssFuzzEnvironment(EnvironmentProtocol):
    def __init__(
        self,
        pool: EnvironmentPoolProtocol,
        environment: EnvironmentProtocol,
        challenge_project_yaml: AIxCCChallengeProjectYaml,
    ):
        super().__init__(pool=pool)
        self.environment = environment
        self._challenge_project_yaml = challenge_project_yaml

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
                raise NotImplementedError("JVM has no specfiic steps for debug build.")

    def _build_for_c(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        # NOTE: **env should come after the ccache environment variables,
        # as we want to prioritize flags defined in higher level classes.
        return self.environment.build(
            context,
            env={
                "CFLAGS": OSS_FUZZ_DEFAULT_CFLAGS + " -O0 -g",
                "CXXFLAGS": OSS_FUZZ_DEFAULT_CXXFLAGS + " -O0 -g",
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
        return self.environment.run_pov(context, detection)

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self.environment.run_tests(context)

    def shell(self, context: EnvironmentContext, command: str) -> tuple[str, str]:
        return self.environment.shell(context, command)

    def execute(
        self, context: EnvironmentContext, command: str, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self.environment.execute(context, command, env)

    def clone(
        self, context: EnvironmentContext, project_name: str
    ) -> EnvironmentProtocol:
        return self.environment.clone(context, project_name)
