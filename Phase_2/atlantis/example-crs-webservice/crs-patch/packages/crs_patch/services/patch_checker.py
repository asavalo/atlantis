import base64
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional

from crs_patch.exceptions.patch_checker import (
    PoVError,
    SourceDirectoryInitError,
)
from crs_patch.models.models import PatchRequest
from crs_patch.utils.challenges import setup_challenge_project
from python_aixcc_challenge.project.functions import check_challenge_docker_image
from python_crs_architecture import CRS_EVALUATOR_DIRECTORY

MAX_RETRIES = 100

logger = logging.getLogger(__name__)


class _ExitCodes:
    SUCCESS = 0
    ERROR = 201
    FAILURE = 202


class PatchChecker:
    """
    # Challenge Evaluator Exit Codes
    Exit Codes:
    0       Success
    201     an error occured
    202     a failure occured
    """

    def __init__(self, evaluator_directory: Optional[Path] = None):
        self.evaluator_directory = evaluator_directory or CRS_EVALUATOR_DIRECTORY
        self.temp_dir = None

    def initialize(self, tarfile_directory: Path):
        self._temp_dir_obj = TemporaryDirectory()
        self.temp_dir = Path(self._temp_dir_obj.name)
        self.source_directory = setup_challenge_project(
            tarfile_directory, self.temp_dir
        )
        self.local_oss_fuzz_directory = self.temp_dir / "fuzz-tooling"
        self.ossfuzz_helper_script = (
            self.local_oss_fuzz_directory / "infra" / "helper.py"
        )

    def restore(self) -> bool:
        try:
            subprocess.check_call(
                "git reset --hard", cwd=self.source_directory, shell=True
            )
            subprocess.check_call(
                "git clean -fdx", cwd=self.source_directory, shell=True
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to restore source directory: {e}")
            return False
        except Exception as e:
            logger.error(f"Error during restore: {e}")
            return False

    def build_image(self, project_name: str):
        if check_challenge_docker_image(project_name):
            return True

        for i in range(MAX_RETRIES):
            try:
                subprocess.check_call(
                    f"{self.ossfuzz_helper_script} build_image --no-pull {project_name}",
                    cwd=self.source_directory,
                    shell=True,
                )
                logger.info(f"Successfully built image for {project_name}")
                return True
            except subprocess.CalledProcessError:
                logger.info(
                    f"Failed to build image, retrying... ({i + 1}/{MAX_RETRIES})"
                )
                time.sleep(10)
                pass

        logger.error(
            f"Failed to build image for {project_name} after {MAX_RETRIES} retries"
        )
        return False

    def check(
        self,
        diff: str,
        request: PatchRequest,
    ):
        if not self.restore():
            logger.error(
                f"Failed to restore source directory {self.source_directory} in check(), continuing"
            )
            return

        logger.info("Checking if patch is applicable...")
        if not self.check_patch_applicable(diff):
            logger.error(
                f"Failed to apply patch (length: {len(diff)}) in check(), continuing"
            )
            return

        logger.info("Checking if OSS-Fuzz helper script is successful...")
        if not self.check_build(request.project_name, diff):
            logger.error(
                f"Failed to build project {request.project_name} with OSS-Fuzz helper {self.ossfuzz_helper_script} in check(), continuing"
            )
            return

        logger.info("Checking if PoV is successful...")
        if not self.check_pov(request):
            raise PoVError("Failed to check PoV")

        ## Skip functional tests as they are not part of the scoring criteria
        ## This is an optimization to reduce test execution time
        # logger.info("Checking if functional tests are successful...")
        # if not self.check_functional_tests(request):
        #     raise FunctionalTestError("Failed to check functional tests")

        logger.info("Patch check passed")

    def check_patch_applicable(
        self,
        diff: str,
    ) -> bool:
        if not self.restore():
            raise SourceDirectoryInitError("Failed to restore source directory")

        with tempfile.NamedTemporaryFile() as diff_file:
            diff_file.write(diff.encode("utf-8"))
            diff_file.flush()
            try:
                subprocess.check_call(
                    f"git -C {self.source_directory} apply --check {diff_file.name}",
                    shell=True,
                )
                return True

            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to apply patch: {e}")
                logger.error(f"error: {e.stderr}")
                return False
            except Exception as e:
                logger.error(f"Error during patch check: {e}")
                return False

    """
    # build the challenge
        action-build-cr/build_cr.sh -p integration-test \
    -r ./integration-test \
    -o ./oss-fuzz-aixcc
    """

    def check_build(
        self,
        project_name: str,
        diff: Optional[str] = None,
    ) -> bool:
        """
        Check if the patch is applicable and if the build is successful.


        Success cases:
        - build_cr.sh return with error code 0

        Error cases:
        - restore fails
        - apply patch fails
        - build_cr.sh return with error code 201 (error)
        - build_cr.sh return with error code 202 (failure)
        - build_cr.sh return with unknown error code
        - build_cr.sh return with unknown exception
        """
        build_script = self.evaluator_directory / "action-build-cr" / "build_cr.sh"

        if not _is_script_executable(build_script):
            logger.error(f"Build script {build_script} is not available")
            return True

        if not self.restore():
            raise SourceDirectoryInitError("Failed to restore source directory")

        if diff:
            with tempfile.NamedTemporaryFile() as diff_file:
                diff_file.write(diff.encode("utf-8", errors="replace"))
                diff_file.flush()
                try:
                    subprocess.check_call(
                        f"git -C {self.source_directory} apply {diff_file.name}",
                        shell=True,
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to apply patch: {e}")
                    return False
                except Exception as e:
                    logger.error(f"Error during patch check: {e}")
                    return False

        try:
            subprocess.check_call(
                f"{build_script} -p {project_name} -r {self.source_directory} -o {self.local_oss_fuzz_directory}",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=True,
            )
        except subprocess.CalledProcessError as e:
            if e.returncode == _ExitCodes.ERROR:
                logger.error(
                    f"Error during OSS-Fuzz build check: {e.returncode}, stderr: {e.stderr}"
                )
                return False
            elif e.returncode == _ExitCodes.FAILURE:
                logger.error(
                    f"Failure during OSS-Fuzz build check: {e.returncode}, stderr: {e.stderr}"
                )
                return False
            else:
                # This should not happen
                logger.error(
                    f"Unexpected error during OSS-Fuzz build check: {e.returncode}, stderr: {e.stderr}"
                )
                return False
        except Exception as e:
            logger.error(f"Unknown error during OSS-Fuzz build check : {e}")
            return False

        return True

    def check_pov(self, request: PatchRequest, timeout: int = 600):
        """
        Check if the PoV is successful. 
        Returns False only when the PoV is intended to crash and actually crashes.

        Example:
            action-run-pov/run_pov.sh -x -n -p integration-test \
                -o ./oss-fuzz-aixcc \
                -b ./integration-test/.aixcc/vulns/vuln_001/blobs/blobs.bin \
                -f fuzz_vuln \
                -e libfuzzer \
                -s address \
                -t 1800

        Success cases:
        - run_pov.sh return 0
        - run_pov.sh return 201 (error)
        - run_pov.sh return unknown error code
        - run_pov.sh return unknown exception

        Error cases:
        - pov fails with error code 202 (failure)
        """

        run_pov_script = self.evaluator_directory / "action-run-pov" / "run_pov.sh"
        if not _is_script_executable(run_pov_script):
            logger.error(f"Run PoV script {run_pov_script} is not available")
            return True

        for blob_info in request.blobs:
            with tempfile.NamedTemporaryFile() as pov_file:
                pov_file.write(base64.b64decode(blob_info.blob_data))
                pov_file.flush()
                try:
                    subprocess.check_call(
                        f"{run_pov_script} -x -p {request.project_name} -o {self.local_oss_fuzz_directory} -b {pov_file.name} -f {blob_info.harness_name} -e libfuzzer -s {blob_info.sanitizer_name} -t {timeout}",
                        cwd=self.evaluator_directory,
                        shell=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except subprocess.CalledProcessError as e:
                    if e.returncode == _ExitCodes.ERROR:
                        logger.error(f"Error during PoV check: {e}")
                        pass
                    elif e.returncode == _ExitCodes.FAILURE:
                        logger.error(f"Failure during PoV check: {e}")
                        return False
                    else:
                        # This should not happen, but we return True to avoid blocking the evaluation
                        logger.error(f"Unexpected error during PoV check: {e}")
                        pass
                except Exception as e:
                    logger.error(f"Unknown error during PoV check: {e}")
                    pass

        return True

    def check_functional_tests(self, request: PatchRequest):
        """
        Check if the functional tests are successful.
        Returns False when the functional tests are intended to fail and actually fail.

        Example:
        action-run-tests/run_tests.sh -p integration-test \
            -r ./integration-test

        Success cases:
        - run_tests.sh return 0
        - run_tests.sh return 201 (error)
        - run_tests.sh return unknown error code
        - run_tests.sh return unknown exception

        Error cases:
        - run_tests.sh return 202 (failure)
        """
        run_tests_script = (
            self.evaluator_directory / "action-run-tests" / "run_tests.sh"
        )
        if not _is_script_executable(run_tests_script):
            logger.error(f"Run tests script {run_tests_script} is not available")
            return True

        test_script = (
            self.local_oss_fuzz_directory
            / "projects"
            / request.project_name
            / "test.sh"
        )
        if not test_script.exists():
            logger.info(f"No tests found for {request.project_name}")
            return True

        try:
            subprocess.check_call(
                f'chmod +x "{test_script}"',
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            logger.error(f"Error chmod +x {test_script}: {e}")
            return True

        try:
            subprocess.check_call(
                f'{run_tests_script} -p {request.project_name} -r {self.source_directory} -t "{test_script}"',
                cwd=self.evaluator_directory,
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except subprocess.CalledProcessError as e:
            if e.returncode == _ExitCodes.ERROR:
                logger.error(f"Error during functional tests check: {e}")
                return True
            elif e.returncode == _ExitCodes.FAILURE:
                logger.error(f"Failure during functional tests check: {e}")
                return False
            else:
                # This should not happen, but we return True to avoid blocking the evaluation
                logger.error(f"Unexpected error during functional tests check: {e}")
                return True
        except Exception as e:
            logger.error(f"Unknown error during functional tests check: {e}")
            return True


def _is_script_executable(script: Path) -> bool:
    if not script.exists():
        logger.error(f"Script {script} does not exist")
        return False

    # check permission excutable
    if not script.stat().st_mode & 0o111:
        logger.error(f"Script {script} is not executable")
        return False

    # check if the script is executable with -h
    exitcode = subprocess.call(
        f"{script} -h",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if exitcode == 0:
        return True
    else:
        logger.error(f"Script {script} is not executable with -h")
        return False
