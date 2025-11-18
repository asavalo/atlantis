import argparse
import functools
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

import coloredlogs
import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)
coloredlogs.install(fmt="%(asctime)s %(levelname)s %(message)s")


def log(message: str):
    logger.info(f"[CRS-TEST-SETUP] {message}")


def error(message: str):
    logger.error(f"[CRS-TEST-SETUP] {message}")


def log_func(func):
    """Decorator to log function entry and exit."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        log(f"Running {func.__name__}")
        try:
            result = func(*args, **kwargs)
            log(f"Exiting {func.__name__}")
            return result
        except Exception as e:
            error(f"Error in {func.__name__}: {str(e)}")
            raise

    return wrapper


def run(cmd: list, env: dict[str, str] | None = None):
    cmd = list(map(str, cmd))

    logger.info(f'[RUN] {" ".join(cmd)}')

    if env is not None:
        logger.info(json.dumps(env, indent=2))
    try:
        combined_env = None
        if env is not None:
            combined_env = os.environ.copy()
            combined_env.update(env)

        ret = subprocess.run(
            " ".join(cmd),
            check=False,
            shell=True,
            # capture_output=True,
            # text=True,
            env=combined_env,
        )

        logger.info(f"Return code: {ret.returncode}")

        if ret.stdout:
            logger.info(f"STDOUT: {ret.stdout}")
        if ret.stderr:
            logger.error(f"STDERR: {ret.stderr}")
        if ret.returncode != 0:
            raise Exception(f"Command failed with return code {ret.returncode}")
        return ret
    except Exception as e:
        error(f"Failed to run command: {e}")
        raise


class SharedDir:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir = root_dir / "build"
        self.out_dir = root_dir / "out"
        self.coverage_dir = root_dir / "coverage"
        self.reachability_dir = root_dir / "reachability"
        self.corpus_dir = root_dir / "corpus"
        self.call_trace_dir = root_dir / "call_trace"
        self.coverage_request_dir = root_dir / "coverage_request"
        self.original_sarif_dir = root_dir / "original_sarif"
        self.pocgen_dir = root_dir / "poc_gen"

        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.coverage_dir.mkdir(parents=True, exist_ok=True)
        self.reachability_dir.mkdir(parents=True, exist_ok=True)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self.call_trace_dir.mkdir(parents=True, exist_ok=True)
        self.coverage_request_dir.mkdir(parents=True, exist_ok=True)
        self.original_sarif_dir.mkdir(parents=True, exist_ok=True)
        self.pocgen_dir.mkdir(parents=True, exist_ok=True)


class MultilangDir:
    def __init__(
        self,
        root_dir: Path,
        original_oss_fuzz_dir: Path,
        project_name: str,
        project_language: str,
    ):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.done_path = self.root_dir / "DONE"
        self.done_path.touch(exist_ok=True)
        original_config_yaml = (
            original_oss_fuzz_dir
            / "projects"
            / "aixcc"
            / project_language
            / project_name
            / ".aixcc"
            / "config.yaml"
        )
        aixcc_config_yaml = self.root_dir / "aixcc_conf.yaml"
        shutil.copy(original_config_yaml, aixcc_config_yaml)


class SarifDir:
    def __init__(
        self,
        root_dir: Path,
        original_oss_fuzz_dir: Path,
        project_name: str,
        project_language: str,
    ):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.build_dir = self.root_dir / "build"
        self.out_dir = self.root_dir / "out"
        self.src_dir = self.root_dir / "src"
        self.work_dir = self.root_dir / "work"
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.src_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)

        original_config_yaml = (
            original_oss_fuzz_dir
            / "projects"
            / "aixcc"
            / project_language
            / project_name
            / ".aixcc"
            / "config.yaml"
        )
        if not Path(self.work_dir / ".aixcc").exists():
            Path(self.work_dir / ".aixcc").mkdir(parents=True, exist_ok=True)

        aixcc_config_yaml = self.work_dir / ".aixcc" / "config.yaml"
        shutil.copy(original_config_yaml, aixcc_config_yaml)

        original_project_yaml = (
            original_oss_fuzz_dir
            / "projects"
            / "aixcc"
            / project_language
            / project_name
            / "project.yaml"
        )
        project_yaml = self.work_dir / "project.yaml"
        shutil.copy(original_project_yaml, project_yaml)


class CPManagerDir:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir = self.root_dir / "out"
        self.src_dir = self.root_dir / "src"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.src_dir.mkdir(parents=True, exist_ok=True)


class JavaDir:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)
        # TODO: Copy the java project from the oss-fuzz dir to the java-dir


class TarballDir:
    def __init__(
        self,
        root_dir: Path,
        tarball_dir: Path,
        project_name: str,
        original_oss_fuzz_dir: Path,
        config_yaml: dict,
        project_yaml: dict,
    ):
        self.project_name = project_name
        self.original_oss_fuzz_dir = original_oss_fuzz_dir
        self.config_yaml = config_yaml
        self.project_yaml = project_yaml

        self.root_dir = root_dir
        self.root_dir.mkdir(parents=True, exist_ok=True)

        # if not (tarball_dir / project_name / "repo.tar.gz").exists():
        #     self.make_tarball(tarball_dir / project_name)

        original_repo_path = tarball_dir / project_name / "repo.tar.gz"
        self.repo_path = self.root_dir / "repo.tar.gz"
        shutil.copy(original_repo_path, self.repo_path)

        original_oss_fuzz_path = tarball_dir / project_name / "oss-fuzz.tar.gz"
        self.oss_fuzz_path = self.root_dir / "oss-fuzz.tar.gz"
        shutil.copy(original_oss_fuzz_path, self.oss_fuzz_path)

        original_diff_path = tarball_dir / project_name / "diff.tar.gz"
        if original_diff_path.exists():
            self.diff_path = self.root_dir / "diff.tar.gz"
            shutil.copy(original_diff_path, self.diff_path)

    def make_tarball(self, project_tarball_dir: Path):
        log(f"Making tarball at {project_tarball_dir}")

        project_tarball_dir.mkdir(parents=True, exist_ok=True)

        main_repo = self.project_yaml["main_repo"]
        full_mode_commit = self.config_yaml["full_mode"]["base_commit"]

        # make repo.tar.gz
        run(["git", "clone", "-b", full_mode_commit, main_repo, self.project_name])
        run(["tar", "-czvf", project_tarball_dir / "repo.tar.gz", self.project_name])
        log(f"Tarball created at {project_tarball_dir / 'repo.tar.gz'}")
        run(["rm", "-rf", self.project_name])

        # make oss-fuzz.tar.gz
        mock_c_ossfuzz_tarball = (
            project_tarball_dir / ".." / "mock-c" / "oss-fuzz.tar.gz"
        )
        run(["tar", "-xvf", mock_c_ossfuzz_tarball])
        run(["rm", "-rf", "./fuzz-tooling/projects/*"])
        run(
            [
                "rsync",
                "-a",
                f"{self.original_oss_fuzz_dir}/aixcc/c/{self.project_name}",
                "./fuzz-tooling/projects/",
            ]
        )
        run(["tar", "-czvf", project_tarball_dir / "oss-fuzz.tar.gz", "fuzz-tooling"])
        log(f"Oss-fuzz tarball created at {project_tarball_dir / 'oss-fuzz.tar.gz'}")

        log(f"Diff mode is not supported in make tarball")


class PocGenDir:
    def __init__(
        self,
        root_dir: Path,
        joern_dir: Path,
        work_dir: Path,
        project_name: str,
        repo_src_path: Path,
        debug_src_dir: Path,
        debug_bin_dir: Path,
        shared_dir: Path,
    ):
        self.root_dir = root_dir
        self.joern_dir = joern_dir
        self.output_dir = self.root_dir / "output"
        self.work_dir = work_dir
        self.cp_name = project_name
        self.repo_src_path = repo_src_path
        self.debug_src_dir = debug_src_dir
        self.debug_bin_dir = debug_bin_dir
        self.shared_dir = shared_dir


class TestSetup:
    def __init__(
        self,
        crs_test_dir: Path,
        original_oss_fuzz_dir: Path,
        working_oss_fuzz_dir: Path,
        project_name: str,
        project_language: str,
        tarball_dir: Path,
        docker_work_dir: Path | None = None,
    ):
        self.crs_test_dir = crs_test_dir
        self.original_oss_fuzz_dir = original_oss_fuzz_dir
        self.oss_fuzz_dir = working_oss_fuzz_dir
        self.project_name = project_name
        if project_language == "cpp":
            self.project_language = "c"
            self.oss_fuzz_language = "cpp"
        else:
            self.project_language = project_language
            self.oss_fuzz_language = project_language

        with open(
            original_oss_fuzz_dir
            / "projects"
            / "aixcc"
            / self.oss_fuzz_language
            / self.project_name
            / "project.yaml",
            "r",
        ) as f:
            project_yaml_data = yaml.safe_load(f)

        with open(
            original_oss_fuzz_dir
            / "projects"
            / "aixcc"
            / self.oss_fuzz_language
            / self.project_name
            / ".aixcc"
            / "config.yaml",
            "r",
        ) as f:
            config_yaml_data = yaml.safe_load(f)
        self.harness_names = [
            harness["name"] for harness in config_yaml_data["harness_files"]
        ]
        if docker_work_dir is None:
            docker_work_dir = Path("/workspace")
        self.docker_work_dir = docker_work_dir

        self.root_dir = self.crs_test_dir / self.project_name

        self.tarball_dir = TarballDir(
            self.root_dir / "tarball_dir",
            tarball_dir,
            project_name,
            original_oss_fuzz_dir,
            config_yaml_data,
            project_yaml_data,
        )

        self.multilang_dir = MultilangDir(
            self.root_dir / "multilang_dir",
            self.original_oss_fuzz_dir,
            self.project_name,
            self.oss_fuzz_language,
        )
        self.sarif_dir = SarifDir(
            self.root_dir / "sarif_dir",
            self.original_oss_fuzz_dir,
            self.project_name,
            self.oss_fuzz_language,
        )
        self.java_dir = JavaDir(self.root_dir / "java_dir")
        self.shared_dir = SharedDir(self.root_dir / "shared_dir")
        self.cp_manager_dir = CPManagerDir(self.root_dir / "cp-manager_dir")
        self.pocgen_dir = PocGenDir(
            Path(os.environ.get("POC_GEN_DIR", "/app/llm-poc-gen")),
            Path(os.environ.get("JOERN_DIR", "/opt/joern")),
            self.sarif_dir.work_dir,
            self.project_name,
            self.cp_manager_dir.src_dir,
            self.sarif_dir.build_dir / "cpg_src",
            self.sarif_dir.build_dir / "debug",
            self.shared_dir.pocgen_dir,
        )


class TestEnv:
    def __init__(self, test_setup: TestSetup):
        self.test_setup = test_setup

    def build_env(self) -> dict[str, str]:
        return {
            "OSS_FUZZ_DIR": str(self.test_setup.oss_fuzz_dir),
            "TARBALL_DIR": str(self.test_setup.tarball_dir.root_dir),
            "REGISTRY": "ghcr.io/team-atlanta",
            "PROJECT_NAME": self.test_setup.project_name,
            "PROJECT_LANGUAGE": self.test_setup.project_language,
            "HARNESS_NAMES": ":".join(self.test_setup.harness_names),
            "SOURCE_DIR": str(self.test_setup.cp_manager_dir.src_dir),
            "OUT_DIR": str(self.test_setup.cp_manager_dir.out_dir),
            "BUILD_SHARED_DIR": str(self.test_setup.shared_dir.build_dir),
            "SVF_MODE": "ander",
            "IMAGE_VERSION": "latest",
            "CODEQL_THREADS": "16",
        }

    def _to_docker_path(self, path: Path) -> str:
        return str(path).replace(
            str(self.test_setup.root_dir), str(self.test_setup.docker_work_dir)
        )

    def crs_env(self) -> dict[str, str]:
        return {
            "VAPI_HOST": "http://localhost:4321",
            "CRS_TARGET": self.test_setup.project_name,
            "CRS_SARIF_REDIS_URL": "redis://redis:6379",
            "CRS_MODE": "debug",
            "BUILD_DIR": self._to_docker_path(self.test_setup.sarif_dir.build_dir),
            "OUT_DIR": self._to_docker_path(self.test_setup.sarif_dir.out_dir),
            "SRC_DIR": self._to_docker_path(self.test_setup.sarif_dir.src_dir),
            "PROJECT_NAME": self.test_setup.project_name,
            "PROJECT_LANGUAGE": self.test_setup.project_language,
            "CP_PROJ_PATH": self._to_docker_path(self.test_setup.sarif_dir.work_dir),
            "CP_SRC_PATH": self._to_docker_path(self.test_setup.sarif_dir.src_dir),
            "TARBALL_DIR": self._to_docker_path(self.test_setup.tarball_dir.root_dir),
            "MULTILANG_BUILD_DIR": self._to_docker_path(
                self.test_setup.multilang_dir.root_dir
            ),
            "BUILD_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.build_dir
            ),
            "COVERAGE_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.coverage_dir
            ),
            "CORPUS_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.corpus_dir
            ),
            "REACHABILITY_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.reachability_dir
            ),
            "CALL_TRACE_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.call_trace_dir
            ),
            "COVERAGE_REQUEST_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.coverage_request_dir
            ),
            "ORIGINAL_SARIF_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.original_sarif_dir
            ),
            "JAVA_CP_METADATA_PATH": self._to_docker_path(
                self.test_setup.java_dir.root_dir
            ),
            "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
            "OPENAI_BASE_URL": os.getenv("OPENAI_BASE_URL"),
            "SANITIZER": "address",
            "FUZZING_ENGINE": "libfuzzer",
            "HELPER": "True",
            "FUZZING_LANGUAGE": self.test_setup.project_language,
            "POCGEN_ROOT_DIR": str(self.test_setup.pocgen_dir.root_dir),
            "POCGEN_JOERN_DIR": str(self.test_setup.pocgen_dir.joern_dir),
            "POCGEN_OUTPUT_DIR": f"{self.test_setup.pocgen_dir.output_dir}_{self.test_setup.project_name}",
            "POCGEN_WORK_DIR": self._to_docker_path(self.test_setup.sarif_dir.work_dir),
            "POCGEN_CP_NAME": self.test_setup.pocgen_dir.cp_name,
            "POCGEN_REPO_SRC_PATH": self._to_docker_path(self.test_setup.pocgen_dir.repo_src_path),
            "POCGEN_DEBUG_SRC_DIR": self._to_docker_path(self.test_setup.pocgen_dir.debug_src_dir),
            "POCGEN_DEBUG_BIN_DIR": self._to_docker_path(self.test_setup.pocgen_dir.debug_bin_dir),
            "POCGEN_SHARED_DIR": self._to_docker_path(
                self.test_setup.shared_dir.pocgen_dir
            ),
        }

    def crs_volumes(self) -> dict[str, str]:
        return {
            "CRS_SARIF_HOST_VOLUME": str(self.test_setup.root_dir.absolute()),
            "CRS_SARIF_DOCKER_VOLUME": str(self.test_setup.docker_work_dir),
        }


def main(args: argparse.Namespace):
    # load env for LLM keys
    load_dotenv(override=True)

    test_setup = TestSetup(
        Path(args.crs_test_dir),
        Path(args.original_oss_fuzz_dir),
        Path(args.working_oss_fuzz_dir),
        args.project_name,
        args.project_language,
        Path(args.tarball_dir),
    )
    test_env = TestEnv(test_setup)

    if args.run_docker_build:
        run(
            [
                "bash",
                "./docker-build.sh",
            ]
        )

    if args.run_sarif_build:
        run(
            [
                "python3",
                "./build.py",
            ],
            env=test_env.build_env(),
        )
        (test_setup.shared_dir.build_dir / "DONE").touch(exist_ok=True)

    if args.run_crs:
        crs_env = test_env.crs_env()
        volumes_env = test_env.crs_volumes()
        crs_env.update(volumes_env)

        # save crs_env to .env.crs_test
        with open(".env.crs_test", "w") as f:
            for key, value in crs_env.items():
                f.write(f"{key}={value}\n")

        # logger.info(json.dumps(crs_env, indent=2))

        run(
            [
                "docker",
                "compose",
                "up",
                "--build",
            ],
            env=crs_env,
        )


if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("--project-name", type=str, required=True)
    args.add_argument("--project-language", type=str, required=True)
    args.add_argument("--original-oss-fuzz-dir", type=str, required=True)
    args.add_argument("--working-oss-fuzz-dir", type=str, required=True)
    args.add_argument("--crs-test-dir", type=str, required=True)
    args.add_argument("--tarball-dir", type=str, required=True)
    args.add_argument("--run-docker-build", action="store_true")
    args.add_argument("--run-sarif-build", action="store_true")
    args.add_argument("--run-crs", action="store_true")
    args = args.parse_args()
    main(args)
