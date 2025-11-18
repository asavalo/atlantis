import random
import re
import tempfile
from pathlib import Path
from typing import Annotated

from pydantic import BeforeValidator
from python_aixcc_challenge.project.functions import (
    check_challenge_docker_image,
    docker_image_name,
)
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.path.globals import OSS_FUZZ_BASE_IMAGE_TAG, OSS_FUZZ_HELPER_FILE

from crete.atoms.detection import Detection
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crete.commons.docker.functions import docker_execute
from crete.commons.interaction.exceptions import CommandInteractionError, TimeoutExpired
from crete.commons.interaction.functions import run_command
from crete.commons.logging.hooks import use_logger
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import (
    ChallengeBuildFailedError,
    ChallengeNotPreparedError,
    ChallengePoVFoundError,
    ChallengeTestFailedError,
    ChallengeWrongPatchError,
)
from crete.framework.environment.functions import (
    check_valid_diff,
    environment_as_command_line_arguments,
    rsync_directory,
)
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol

CommitStr = Annotated[
    str, BeforeValidator(lambda x: x if re.match(r"^[a-f0-9]{40}$", x) else None)
]

CHECK_BUILD_TIMEOUT = 10 * 60  # 10 minutes
RUN_POV_TIMEOUT = 10 * 60  # 10 minutes
RUN_TESTS_TIMEOUT = 5 * 60  # 5 minutes
SHELL_TIMEOUT = 5 * 60  # 5 minutes


_logger = use_logger(__name__)


class OssFuzzEnvironment(EnvironmentProtocol):
    def __init__(
        self,
        pool: EnvironmentPoolProtocol,
        project_name: str,
        checkout_ref: CommitStr,
        max_timeout: int,
    ) -> None:
        super().__init__(pool=pool)
        self._project_name = project_name
        self._checkout_ref = checkout_ref

        self._max_timeout = max_timeout
        self._build_timeout = max_timeout
        self._run_tests_timeout = RUN_TESTS_TIMEOUT
        self._check_build_timeout = CHECK_BUILD_TIMEOUT
        self._run_pov_timeout = RUN_POV_TIMEOUT
        self._shell_timeout = SHELL_TIMEOUT

    def restore(self, context: EnvironmentContext) -> tuple[str, str]:
        return self._initialize_source_directory()

    def _from_elapsed_time_to_timeout(self, elapsed_time: int) -> int:
        # 1. 2 times elapsed time
        # 2. add 30 seconds (for adding some margin)
        # 3. use 5 minutes as the minimum timeout
        # 4. clamp to max timeout
        return min(max(elapsed_time * 2 + 30, 10 * 60), self._max_timeout)

    def set_timeout(
        self, context: EnvironmentContext, build_time: int, run_tests_time: int
    ) -> None:
        self._build_timeout = self._from_elapsed_time_to_timeout(build_time)
        self._run_tests_timeout = self._from_elapsed_time_to_timeout(run_tests_time)

        context["logger"].info(
            "Setting timeouts\n"
            f"  - build: {self._build_timeout} (original: {build_time})\n"
            f"  - run tests: {self._run_tests_timeout} (original: {run_tests_time})"
        )

    def check_build(self, context: EnvironmentContext) -> tuple[str, str]:
        sanitizer_name = context.get("sanitizer_name", "address")

        command = (
            f"{OSS_FUZZ_HELPER_FILE} check_build {self._project_name} --sanitizer {sanitizer_name}",
            self.pool.source_directory,
        )

        try:
            stdout, stderr = run_command(
                command=command,
                timeout=self._check_build_timeout,
                no_color=True,
            )
            return stdout, stderr
        except CommandInteractionError as e:
            raise ChallengeBuildFailedError(stdout=e.stdout, stderr=e.stderr) from e
        except TimeoutExpired as e:
            raise ChallengeBuildFailedError(stdout=e.stdout, stderr=e.stderr) from e

    def build(
        self,
        context: EnvironmentContext,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        if not check_challenge_docker_image(self._project_name):
            raise ChallengeNotPreparedError(stdout=b"", stderr=b"")

        try:
            self.execute(context, "rm -rf /out/*")

            environment_arguments = environment_as_command_line_arguments(env)

            sanitizer_name = context.get("sanitizer_name", "address")

            command = (
                f"{OSS_FUZZ_HELPER_FILE} build_fuzzers {self._project_name} {self.pool.source_directory} --sanitizer {sanitizer_name} {environment_arguments}",
                self.pool.source_directory,
            )

            build_stdout, build_stderr = run_command(
                command=command,
                timeout=self._build_timeout,
                no_color=True,
            )

            return build_stdout, build_stderr
        except CommandInteractionError as e:
            raise ChallengeBuildFailedError(
                stdout=cleanup_build_logs(e.stdout),
                stderr=cleanup_build_logs(e.stderr),
            ) from e
        except TimeoutExpired as e:
            raise ChallengeBuildFailedError(
                stdout=cleanup_build_logs(e.stdout),
                stderr=cleanup_build_logs(e.stderr),
            ) from e

    def patch(
        self,
        context: EnvironmentContext,
        patch: Path | bytes,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        match patch:
            case Path():
                return self._patch_internal(context, patch, env)
            case bytes():
                with tempfile.NamedTemporaryFile() as f:
                    f.write(patch)
                    f.flush()

                    return self._patch_internal(context, Path(f.name), env)

    def _patch_internal(
        self,
        context: EnvironmentContext,
        patch_file: Path,
        env: dict[str, str],
    ) -> tuple[str, str]:
        # NOTE: This assumes that the environment is already restored
        try:
            _logger.info(f"Checking valid diff: {patch_file}")
            check_valid_diff(
                patch_file.read_text(),
                self.pool.source_directory,
                AIxCCChallengeProjectYaml.from_project_name(
                    self._project_name
                ).language,
            )
        except ChallengeWrongPatchError as e:
            raise e
        except Exception:
            _logger.warning(
                f"Unknown error while checking valid diff. Ignoring: {patch_file}"
            )

        try:
            run_command(
                (f"git apply {patch_file}", self.pool.source_directory),
                timeout=self._shell_timeout,
            )

        except (CommandInteractionError, TimeoutExpired) as e:
            raise ChallengeWrongPatchError(stdout=e.stdout, stderr=e.stderr) from e

        return self.build(context, env)

    def run_pov(
        self, context: EnvironmentContext, detection: Detection
    ) -> tuple[str, str]:
        assert len(detection.blobs) > 0, "At least one blob is required"

        stdout, stderr = "", ""
        for blobinfo in detection.blobs:
            stdout, stderr, success = self._run_pov(
                context, blobinfo.blob, blobinfo.harness_name
            )
            if not success:
                raise ChallengePoVFoundError(
                    stdout=stdout.encode(errors="ignore"),
                    stderr=stderr.encode(errors="ignore"),
                )
        return stdout, stderr

    def _run_pov(
        self, context: EnvironmentContext, blob: bytes, harness_name: str
    ) -> tuple[str, str, bool]:
        return self._run_pov_with_retry(
            context=context,
            blob=blob,
            harness_name=harness_name,
            timeout=self._run_pov_timeout,
        )

    def _run_pov_with_retry(
        self,
        context: EnvironmentContext,
        blob: bytes,
        harness_name: str,
        timeout: int,
        is_retry: bool = False,
    ) -> tuple[str, str, bool]:
        try:
            with tempfile.NamedTemporaryFile(delete_on_close=False) as blob_file:
                blob_file.write(blob)
                blob_file.close()

                command = f"{OSS_FUZZ_HELPER_FILE} reproduce {self._project_name} {harness_name} {blob_file.name}"
                if is_retry:
                    command += " -- -runs=1"

                return (
                    *run_command(
                        command=(
                            command,
                            self.pool.source_directory,
                        ),
                        timeout=timeout,
                        no_color=True,
                    ),
                    True,
                )
        except CommandInteractionError as e:
            return (
                e.stdout.decode(errors="replace"),
                e.stderr.decode(errors="replace"),
                False,
            )
        except TimeoutExpired:
            if is_retry:
                context["logger"].warning(
                    "Timeout even we retried to reproduce PoV. So consider it as unreproducible"
                )
                return "", "", True
            else:
                return self._run_pov_with_retry(
                    context=context,
                    blob=blob,
                    harness_name=harness_name,
                    timeout=(self._run_pov_timeout // 5),
                    is_retry=True,
                )

    def run_tests(
        self, context: EnvironmentContext, env: dict[str, str] = {}
    ) -> tuple[str, str]:
        if not self.pool.internal_test_exists():
            return "Tests skipped. No tests found.", ""

        # This tries to replicate the command in run_tests.sh mentioned in #1213.
        docker_image = docker_image_name(self._project_name)
        test_script_abs = self.pool.internal_test_script_path().resolve()
        assert test_script_abs.exists(), f"test.sh not found at {test_script_abs}"

        # Destination paths in the docker container.
        local_src_mnt = "/local-source-mount"
        test_mnt = "/test-mnt.sh"

        # Instead of using `docker inspect` like the original run_tests.sh to get $WORK_DIR,
        # we use $PWD which achieves the same result more efficiently.
        #
        # Also, we add chmod +x to ensure test.sh is executable,
        # since it was provided without execute permissions (see #1213).
        cmd = [
            "/bin/bash",
            "-c",
            f"WORK_DIR=$PWD && \
                pushd $SRC && rm -rf $WORK_DIR \
                && cp -r {local_src_mnt} $WORK_DIR \
                && cp {test_mnt} ${{SRC}}/test.sh \
                && chmod +x ${{SRC}}/test.sh \
                && popd && ${{SRC}}/test.sh",
        ]

        try:
            return docker_execute(
                # NOTE: We assume that helper.py does not modify docker image name format (aixcc-afc/...).
                image=docker_image,
                cmd=cmd,
                files_to_mount=[
                    (self.pool.source_directory, local_src_mnt),
                    (test_script_abs, test_mnt),
                    (self.pool.work_directory, "/work"),
                ],
                env=env,
                timeout=self._run_tests_timeout,
            )
        except CommandInteractionError as e:
            raise ChallengeTestFailedError(e.stdout, e.stderr)
        except TimeoutExpired as e:
            raise e

    def shell(self, context: EnvironmentContext, command: str) -> tuple[str, str]:
        return run_command(
            command=(
                f"{OSS_FUZZ_HELPER_FILE} shell {self._project_name} {self.pool.source_directory}",
                self.pool.source_directory,
            ),
            timeout=self._shell_timeout,
            input=f"{command}; exit $?".encode(),
            isatty=True,
            no_color=True,
        )

    def execute(
        self,
        context: EnvironmentContext,
        command: str,
        env: dict[str, str] = {},
    ) -> tuple[str, str]:
        environment_arguments = environment_as_command_line_arguments(env)
        return run_command(
            command=(
                f"{OSS_FUZZ_HELPER_FILE} execute {self._project_name} {self.pool.source_directory} --exec '{command}' {environment_arguments}",
                self.pool.source_directory,
            ),
            timeout=self._shell_timeout,
            no_color=True,
        )

    def clone(
        self, context: EnvironmentContext, project_name: str
    ) -> "EnvironmentProtocol":
        new_source_directory = DEFAULT_CACHE_DIRECTORY / "sources" / project_name
        rsync_directory(self.pool.source_directory, new_source_directory)
        return OssFuzzEnvironment(
            pool=self.pool,
            project_name=project_name,
            checkout_ref=self._checkout_ref,
            max_timeout=self._max_timeout,
        )

    def _initialize_source_directory(self):
        command = f'git config --global --add safe.directory "*"; git reset --hard {self._checkout_ref}; git clean -ffdx'
        return self._docker_execute(command, self.pool.source_directory)

    def _docker_execute(self, command: str, workdir: Path):
        docker_command = f"docker run --rm --workdir={workdir} -v {workdir}:{workdir} ghcr.io/aixcc-finals/base-runner:{OSS_FUZZ_BASE_IMAGE_TAG} sh -c '{command}'"
        return run_command((docker_command, Path.cwd()))


def add_bashrc(env: dict[str, str], target_directory: Path, bash_script: str) -> str:
    def _choose_bashenv_path(bash_env: str | None) -> str:
        if bash_env is not None:
            if match := re.match(r"/work/bashrc([0-9]+)", bash_env):
                return f"/work/bashrc{int(match.group(1)) + 1}"
            else:
                return "/work/bashrc%s" % random.getrandbits(64)
        else:
            return "/work/bashrc0"

    old_bashrc_path = env.get("BASH_ENV")
    new_bashrc_path = _choose_bashenv_path(old_bashrc_path)
    assert new_bashrc_path.startswith("/work/")

    if old_bashrc_path is not None:
        bash_script = f"{bash_script}\nsource {old_bashrc_path}\n"

    (target_directory / new_bashrc_path.removeprefix("/work/")).write_text(bash_script)
    return new_bashrc_path


def cleanup_build_logs(log: bytes) -> bytes:
    """
    Remove maven download logs from build logs which consumes 100s of lines

    Example:
    Downloading from central: https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-shade-plugin/3.2.4/maven-shade-plugin-3.2.4.pom
    Progress (1): 1.4/11 kB
    Downloaded from central: https://repo.maven.apache.org/maven2/com/google/errorprone/error_prone_annotations/2.2.0/error_prone_annotations-2.2.0.jar (14 kB at 428 kB/s)
    """

    # NOTE: "+" below is line-level, so it doesn't remove all the lines after the needles.
    original_size = len(log)
    log = re.sub(rb"Downloading from [^\s]+: .*\n*", b"", log)
    log = re.sub(rb"Downloaded from [^\s]+: .* \(.*\)\n*", b"", log)
    log = re.sub(rb"Progress \(.*\): .*\n*", b"", log)

    new_size = len(log)
    diff = original_size - new_size
    reduction = diff / original_size if original_size > 0 else 0

    _logger.debug(
        f"Cleaned up build logs: {original_size} -> {new_size} "
        f"({diff} bytes, {reduction * 100:.2f}%)"
    )
    return log
