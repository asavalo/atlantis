from pathlib import Path

from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml

from crete.atoms.detection import Detection
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment.services.oss_fuzz.default import add_bashrc
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


class CachedOssFuzzEnvironment(EnvironmentProtocol):
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
        return self.environment.build(context, self._add_cache_to_env(env))

    def patch(
        self,
        context: EnvironmentContext,
        patch: Path | bytes,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        return self.environment.patch(context, patch, self._add_cache_to_env(env))

    def check_build(self, context: EnvironmentContext) -> tuple[str, str]:
        return self.environment.check_build(context)

    def _add_cache_to_env(self, env: dict[str, str]) -> dict[str, str]:
        match self._challenge_project_yaml.language:
            case "c" | "c++" | "cpp":
                env = _install_ccache(env, self.pool.work_directory)
            case "jvm":
                env = _redirect_maven_repository(env, self.pool.work_directory)
        return env

    def run_pov(
        self, context: EnvironmentContext, detection: Detection
    ) -> tuple[str, str]:
        assert len(detection.blobs) > 0, "At least one blob is required"
        return self.environment.run_pov(context, detection)

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        return self.environment.run_tests(context, self._add_cache_to_env(env))

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


def _install_ccache(env: dict[str, str], target_directory: Path) -> dict[str, str]:
    _CCACHE_CLANG_SCRIPT = """#!/bin/bash
command=$(which $(basename $0))
ccache ${command} "$@"
"""

    (target_directory / "ccache").mkdir(parents=True, exist_ok=True)
    for compiler in ["clang", "clang++"]:
        if not (target_directory / "ccache" / compiler).exists():
            wrapper_path = target_directory / "ccache" / compiler
            wrapper_path.write_text(_CCACHE_CLANG_SCRIPT)
            wrapper_path.chmod(0o755)

    # NOTE: **env should come after the ccache environment variables,
    # as we want to prioritize flags defined in higher level classes.
    return {
        "CCACHE_DIR": "/work/ccache/cache",
        "CC": "/work/ccache/clang",
        "CXX": "/work/ccache/clang++",
        **env,
    }


def _append_flags(flags: str, new_flags: str) -> str:
    if flags:
        return f"{flags} {new_flags}"
    return new_flags


def _install_maven_build_cache(
    env: dict[str, str], target_directory: Path
) -> dict[str, str]:
    SCRIPTS_DIRECTORY = Path(__file__).parent / "scripts" / "cached"
    ADD_JCACHE_TO_SDKMAN = (SCRIPTS_DIRECTORY / "bash-init.sh").read_text()
    MVN_SCRIPT = (SCRIPTS_DIRECTORY / "mvn-wrapper.py").read_text()

    (target_directory / "mvn-wrapper").mkdir(parents=True, exist_ok=True)
    mvn_path = target_directory / "mvn-wrapper" / "mvn"
    mvn_path.write_text(MVN_SCRIPT)
    mvn_path.chmod(0o755)

    return {
        "BASH_ENV": add_bashrc(env, target_directory, ADD_JCACHE_TO_SDKMAN),
        "MAVEN_OPTS": "-Dmaven.build.cache.location=/work/maven-build-cache",
        **env,
    }


# Temporarily disabled (#1003)
del _install_maven_build_cache


def _redirect_maven_repository(
    env: dict[str, str], work_directory: Path
) -> dict[str, str]:
    """
    Configure Maven to use a shared cache directory with maximum compatibility.

    This function:
    1. Creates a symbolic link from ~/.m2/repository to /work/mavencache to support hardcoded paths
    2. Sets MAVEN_OPTS to use the shared cache location

    Note: The cache may not be used if:
    - Build script explicitly overrides the Maven repository path (build is slower but still succeeds)
    - Build script is somehow not compatible with the cache and build fails (falls back to default env)
    """
    MAVEN_CACHE_DIR = "/work/mavencache"

    # Copy environment to avoid modifying original
    env = env.copy()

    # 1. Set up symbolic link via bash script, from ~/.m2/repository to /work/mavencache
    redirect_script = (
        Path(__file__).parent / "scripts" / "cached" / "redirect-maven-repository.sh"
    ).read_text()
    env["BASH_ENV"] = add_bashrc(env, work_directory, redirect_script)

    # 2. Set MAVEN_OPTS to use the shared cache location
    maven_opts = env.get("MAVEN_OPTS", "")
    env["MAVEN_OPTS"] = _append_flags(
        maven_opts, f"-Dmaven.repo.local={MAVEN_CACHE_DIR}"
    )

    return env
