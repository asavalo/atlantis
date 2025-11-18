import fnmatch
import functools
import hashlib
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Optional

import docker
import yaml
from docker import from_env
from docker.models.containers import Container
from loguru import logger

print(os.environ)

SOURCE_DIR = Path(os.environ["SOURCE_DIR"])
COMPILED_SRC_DIR = SOURCE_DIR / "compiled_src"
os.makedirs(SOURCE_DIR, exist_ok=True)
os.makedirs(COMPILED_SRC_DIR, exist_ok=True)
TARBALL_DIR = Path(os.environ["TARBALL_DIR"])


OSS_FUZZ_DIR = SOURCE_DIR / "fuzz-tooling"

REGISTRY = os.getenv("REGISTRY", "ghcr.io/team-atlanta")
SARIF_BASE_IMAGE = REGISTRY + "/crs-sarif"
# SARIF_CRS_IMAGE = SARIF_BASE_IMAGE + "/crs-sarif"
SARIF_BUILDER_C_IMAGE = SARIF_BASE_IMAGE + "/sarif-builder"
SARIF_BUILDER_JVM_IMAGE = SARIF_BASE_IMAGE + "/sarif-builder-jvm"
IMAGE_VERSION = os.getenv("IMAGE_VERSION", "latest")

PROJECT_NAME = os.getenv("PROJECT_NAME", "mock-java")
PROJECT_LANGUAGE = os.getenv("PROJECT_LANGUAGE", "jvm")
HARNESS_NAMES = os.getenv("HARNESS_NAMES", "OssFuzz1")

IS_BENCHMARK = os.getenv("IS_BENCHMARK", "True")
CODEQL_THREADS = os.getenv("CODEQL_THREADS", "24")
SVF_PARALLEL = os.getenv("SVF_PARALLEL", "False").lower() in ("true", "1", "yes")
SVF_MAX_WORKERS = int(os.getenv("SVF_MAX_WORKERS", "1"))
ULIMIT_MEM = int(os.getenv("ULIMIT_MEM", str(48 * 1024 * 1024)))
WPA_TIMEOUT = int(os.getenv("WPA_TIMEOUT", str(20 * 60)))
# SVF_PARALLEL = os.getenv("SVF_PARALLEL", "True").lower() in ("true", "1", "yes")
# SVF_MAX_WORKERS = int(os.getenv("SVF_MAX_WORKERS", "4"))

CPG_BUILD_TIMEOUT = int(os.getenv("CPG_BUILD_TIMEOUT", str(1200)))

SARIF_BUILDER_IMAGE = SARIF_BUILDER_C_IMAGE
if PROJECT_LANGUAGE == "jvm":
    SARIF_BUILDER_IMAGE = SARIF_BUILDER_JVM_IMAGE

# ORIGINAL_BUILD_DIR = Path(os.getenv("ORIGINAL_BUILD_DIR"))

OUT_DIR = Path(
    os.getenv("BUILDER_OUT_DIR")
)  # Shared out dir. CRS-SARIF will copy built files here
os.makedirs(OUT_DIR, exist_ok=True)

SVF_OUT_DIR = OUT_DIR / "SVF"
CODEQL_OUT_DIR = OUT_DIR / "codeql"
JOERN_OUT_DIR = OUT_DIR / "joern"
SOOTUP_OUT_DIR = OUT_DIR / "sootup"
ORIGINAL_DIR = OUT_DIR / "original"

BUILD_SHARED_DIR = Path(os.getenv("BUILD_SHARED_DIR"))
if not BUILD_SHARED_DIR.exists():
    BUILD_SHARED_DIR.mkdir(parents=True, exist_ok=True)

SVF_MODE = os.getenv("SVF_MODE", "ander")

DOCKER_BUILD_ENV = {
    "FUZZING_ENGINE": "libfuzzer",
    "SANITIZER": "address",
    "ARCHITECTURE": "x86_64",
    "PROJECT_NAME": PROJECT_NAME,
    "HELPER": "True",
    "FUZZING_LANGUAGE": PROJECT_LANGUAGE,
}

# ENV for llm-poc-gen
DEBUG_DIR = OUT_DIR / "debug"
CPG_SRC_DIR = OUT_DIR / "cpg_src"

WORKDIR_REGEX = re.compile(r"\s*WORKDIR\s*([^\s]+)")

# Thread-safe logging lock for parallel operations
_log_lock = Lock()


def log(message: str):
    with _log_lock:
        logger.info(f"[SARIF-BUILDER] {message}")


def error(message: str):
    with _log_lock:
        logger.error(f"[SARIF-BUILDER] {message}")


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


@log_func
def setup_challenge_project(
    tarfile_dir: Path = TARBALL_DIR,
    output_dir: Path = SOURCE_DIR,
) -> Path:
    shared_repo_tarfile = tarfile_dir / "repo.tar.gz"
    if not shared_repo_tarfile.exists():
        raise ValueError(f"Repo tarfile {shared_repo_tarfile} does not exist")

    repo_tarfile = output_dir / "repo.tar.gz"
    shutil.copy(shared_repo_tarfile, repo_tarfile)

    shared_diff_tarfile = tarfile_dir / "diff.tar.gz"
    if not shared_diff_tarfile.exists():
        diff_tarfile = None
    else:
        diff_tarfile = output_dir / "diff.tar.gz"
        shutil.copy(shared_diff_tarfile, diff_tarfile)

    shared_oss_fuzz_tarfile = tarfile_dir / "oss-fuzz.tar.gz"
    if not shared_oss_fuzz_tarfile.exists():
        raise ValueError(f"OSS-Fuzz tarfile {shared_oss_fuzz_tarfile} does not exist")

    oss_fuzz_tarfile = output_dir / "oss-fuzz.tar.gz"
    shutil.copy(shared_oss_fuzz_tarfile, oss_fuzz_tarfile)

    return setup_challenge_project_from_tarfiles(
        repo_tarfile, oss_fuzz_tarfile, output_dir, diff_tarfile
    )


@log_func
def setup_challenge_project_from_tarfiles(
    source_tarfile: Path,
    oss_fuzz_tarfile: Path,
    output_dir: Path = SOURCE_DIR,
    diff_tarfile: Optional[Path] = None,
) -> Path:
    # Extract oss-fuzz tarball
    _extract_tarfile(oss_fuzz_tarfile, output_dir)
    # _modify_dockerfile(OSS_FUZZ_DIR / "projects" / PROJECT_NAME)

    # Extract the project source tarball
    source_dir = _extract_repo_tarfile(source_tarfile, output_dir)

    if diff_tarfile is not None:
        # Extract the diff tarball
        _extract_tarfile(diff_tarfile, output_dir)

        diff_file = Path("../diff/ref.diff")
        # init
        subprocess.run("git init .", cwd=source_dir, shell=True, check=True)

        # apply
        try:
            result = subprocess.run(
                f"git apply --reject {diff_file}",
                cwd=source_dir,
                shell=True,
                check=True,
                capture_output=True,
                text=True,
            )
            if result.stdout:
                logger.info(f"Git apply stdout: {result.stdout}")
        except Exception as e:
            if hasattr(e, "stderr"):
                logger.error(f"Git apply command failed: {e.stderr}")
            if hasattr(e, "stdout"):
                logger.warning(f"Git apply stdout: {e.stdout}")

        # remove .git
        try:
            subprocess.run("rm -rf .git", cwd=source_dir, shell=True, check=True)
        except Exception:
            logger.info(f"No git repo found in {source_dir}")

    # tarball extraction done
    (BUILD_SHARED_DIR / "EXTRACT_DONE").touch()

    return source_dir


def __extract_base_image(dockerfile):
    for line in dockerfile.split("\n"):
        line = line.strip()
        tokens = list(filter(lambda x: x != "", line.split(" ")))
        if len(tokens) < 2:
            continue
        if tokens[0] not in ["FROM", "from"]:
            continue
        return tokens[1]


def _rewrite_dockerfile(
    original_dockerfile: Path, modified_dockerfile: Path, codeql: bool = False
):
    prev = original_dockerfile.read_text()

    new = prev
    base_image = __extract_base_image(prev)
    base_url = base_image.split(":")[0]
    if codeql:
        new_url = f"{REGISTRY}/crs-sarif/sarif-builder-codeql"
    else:
        new_url = f"{REGISTRY}/crs-sarif/sarif-builder"
    if base_url.endswith("-jvm"):
        new_url += "-jvm"
    new_url += f":{IMAGE_VERSION}"
    new = new.replace(base_image, new_url)
    modified_dockerfile.write_text(new)


def _modify_dockerfile(target_project_dir: Path, codeql: bool = False) -> Path:
    original_dockerfile = target_project_dir / "Dockerfile"
    dockerfile_name = (
        "Dockerfile.sarif_builder" if not codeql else "Dockerfile.sarif_builder_codeql"
    )
    modified_dockerfile = target_project_dir / dockerfile_name
    _rewrite_dockerfile(original_dockerfile, modified_dockerfile, codeql)

    return modified_dockerfile


def _extract_repo_tarfile(tar_path: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    members = _extract_tarfile(tar_path, output_dir)

    return output_dir / members[0].name


def _extract_tarfile(tar_path: Path, output_dir: Path):
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(output_dir)
        return tar.getmembers()


@log_func
def _archive_dir_shell(
    dir: Path, tar_path: Path, exclude_patterns: Optional[list[str]] = None
):
    # To ignore files that cannot be read due to permissions or other issues
    if not dir.is_dir():
        error(f"Source directory does not exist or is not a directory: {dir}")
        return False

    tar_path.parent.mkdir(parents=True, exist_ok=True)

    source_dir_parent = dir.parent
    source_dir_name = dir.name

    command = [
        "tar",
        "czf",
        str(tar_path.resolve()),
        "--ignore-failed-read",
    ]

    if exclude_patterns:
        for pattern in exclude_patterns:
            command.append(f"--exclude={pattern}")

    command.extend(
        [
            "-C",
            str(source_dir_parent.resolve()),
            source_dir_name,
        ]
    )

    log(f"Running tar command: {' '.join(command)}")

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        log(f"Tar command completed successfully for {dir}.")
        log(f"Tar stdout: {result.stdout}")
        log(f"Tar stderr: {result.stderr}")
        return True
    except FileNotFoundError:
        error(f"'tar' command not found. Please ensure tar is installed and in PATH.")
        return False
    except subprocess.CalledProcessError as e:
        error(f"Tar command failed for {dir} with exit code {e.returncode}.")
        error(f"Tar stderr: {e.stderr}")
        error(f"Tar stdout: {e.stdout}")
        return False
    except Exception as e:
        error(f"An unexpected error occurred during tar command execution: {e}")
        return False


def setup_docker_volumes():
    SVF_OUT_DIR.mkdir(parents=True, exist_ok=True)
    CODEQL_OUT_DIR.mkdir(parents=True, exist_ok=True)
    JOERN_OUT_DIR.mkdir(parents=True, exist_ok=True)
    ORIGINAL_DIR.mkdir(parents=True, exist_ok=True)


class DockerExecError(Exception): ...


class OssFuzzDocker:
    def __init__(
        self,
        project_name: str,
        project_language: str,
        source_dir: Path,
        codeql: bool = False,
    ):
        self.project_name = project_name
        self.project_language = project_language
        project_yaml_path = OSS_FUZZ_DIR / "projects" / project_name / "project.yaml"
        self.proj_yaml = yaml.safe_load(project_yaml_path.read_text())
        self.source_dir = source_dir
        self.container: Container | None = None
        self.codeql = codeql
        if codeql:
            self.image_name = f"aixcc-afc/{self.project_name}-sarif-codeql"
        else:
            self.image_name = f"aixcc-afc/{self.project_name}-sarif"

        self.client = from_env()

        self._build_image()

    def exec(
        self,
        cmd: str,
        env: dict | None = None,
        work_dir: str | None = None,
        isPrint: int = 1,
        timeout: int | None = None,
    ) -> bool:
        if env is None:
            env = dict()

        for container_env in self.container.attrs["Config"]["Env"]:
            if container_env.startswith("PATH="):
                env["PATH"] = container_env.split("=")[1]
                break

        if timeout != None:
            cmd = f"timeout {timeout}s {cmd}"

        result = self.container.exec_run(
            cmd, stdout=True, stderr=True, environment=env, workdir=work_dir
        )
        if isPrint:
            log(f"Command output: {result.output.decode()}")
        if result.exit_code == 124:
            error("Command timed out. Skip creating cpg.")
            raise TimeoutError
        elif result.exit_code != 0:
            error(f"Command failed with exit code: {result.exit_code}")
            raise DockerExecError

        return result

    @log_func
    def _build_image(self):
        # subprocess.run(
        #     # f"python3 {OSS_FUZZ_HELPER} build_fuzzers {self.project_name} {self.source_dir.absolute()}",
        #     f"python3 {OSS_FUZZ_HELPER} build_image {self.project_name} --pull",
        #     shell=True,
        # )
        modified_dockerfile = _modify_dockerfile(
            OSS_FUZZ_DIR / "projects" / self.project_name, self.codeql
        )

        docker_proj_path = OSS_FUZZ_DIR / "projects" / self.project_name
        # dockerfile_path = docker_proj_path / "Dockerfile"

        subprocess.run(
            f"docker build -t {self.image_name} -f {modified_dockerfile.absolute()} {docker_proj_path.absolute()}",
            shell=True,
        )

    def _workdir_from_lines(self, lines, default="/src"):
        for line in reversed(lines):  # reversed to get last WORKDIR.
            match = re.match(WORKDIR_REGEX, line)
            if match:
                workdir = match.group(1)
                workdir = workdir.replace("$SRC", "/src")

                if not os.path.isabs(workdir):
                    workdir = os.path.join("/src", workdir)

                return os.path.normpath(workdir)

        return default

    def _workdir_from_dockerfile(self, dockerfile_path):
        with open(dockerfile_path) as file_handle:
            lines = file_handle.readlines()

        return self._workdir_from_lines(
            lines, default=(Path("/src") / self.project_name)
        )

    def _get_workdir_from_dockerfile(self):
        dockerfile_path = OSS_FUZZ_DIR / "projects" / self.project_name / "Dockerfile"
        return self._workdir_from_dockerfile(dockerfile_path)

    def _get_workdir(self):
        return self.exec("pwd").output.decode().strip()

    def download_source(self, local_dir: Path):
        work_dir = self._get_workdir()

        local_dir.mkdir(parents=True, exist_ok=True)

        try:
            stream, _ = self.container.get_archive(work_dir + "/.")
            file_bytes = b"".join(chunk for chunk in stream)

            with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tar:
                tar.extractall(path=local_dir)

            log(f"Successfully downloaded source from container to {local_dir}")

        except Exception as e:
            error(f"Failed to download source from container: {e}")
            raise

    def _copy_source(self):
        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            tar.add(self.source_dir.absolute(), arcname=".")
        tarstream.seek(0)

        work_dir = self._get_workdir()

        self.exec(f"rm -rf {work_dir}", work_dir="/")
        self.exec(f"mkdir -p {work_dir}", work_dir="/")

        self.container.put_archive(work_dir, tarstream)

    def _copy_file_to_container(self, file_path: Path, container_path: str):
        container_dir = os.path.dirname(container_path)
        container_filename = os.path.basename(container_path)

        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            tar.add(file_path, arcname=container_filename)
        tarstream.seek(0)

        self.container.put_archive(container_dir, tarstream)

    def _copy_files_from_container(self, container_path: str, output_dir: str):
        exclude_dirs = {"aflplusplus", "fuzztest", "honggfuzz", "libfuzzer", ".git"}

        allowed_patterns = [
            "*.c",
            "*.c.in",
            "*.C",
            "*.m",
            "*.cc",
            "*.cxx",
            "*.cpp",
            "*.cp",
            "*.ccm",
            "*.cxxm",
            "*.c++m",
            "*.c++",
            "*.cpp.in",
            "*.mm",
            "*.h",
            "*.H",
            "*.h.in",
            "*.inc",
            "*.hpp",
            "*.hh",
            "*.hp",
            "*.hxx",
            "*.h++",
            "*.tcc",
            "*.hpp.in",
            "*.inl",
        ]

        os.makedirs(output_dir, exist_ok=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            stream, _ = self.container.get_archive(container_path)
            file_bytes = b"".join(chunk for chunk in stream)

            with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tar:
                tar.extractall(path=temp_dir)

            extracted_path = os.path.join(temp_dir, os.path.basename(container_path))

            for root, dirs, files in os.walk(extracted_path):
                dirs[:] = [d for d in dirs if d not in exclude_dirs]

                for file in files:
                    if not any(
                        fnmatch.fnmatch(file, pattern) for pattern in allowed_patterns
                    ):
                        continue
                    src_path = os.path.join(root, file)
                    relative_path = os.path.relpath(src_path, extracted_path)
                    dst_path = os.path.join(output_dir, relative_path)

                    try:
                        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                        shutil.copy2(src_path, dst_path)
                    except Exception:
                        continue

    def _read_file_from_container(self, container_path: str):
        with tempfile.TemporaryDirectory() as temp_dir:
            stream, stat = self.container.get_archive(container_path)
            file_bytes = b"".join(chunk for chunk in stream)

            with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tar:
                tar.extractall(path=temp_dir)

            extracted_file_path = os.path.join(
                temp_dir, os.path.basename(container_path)
            )
            with open(extracted_file_path, "r") as f:
                lines = f.readlines()

            return lines

    @log_func
    def _start_container(self) -> Container:
        self.container = self.client.containers.run(
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
            environment=DOCKER_BUILD_ENV,
            privileged=True,
            shm_size="2g",
            platform="linux/amd64",
            volumes={
                str(OUT_DIR.absolute()): {
                    "bind": "/out",
                    "mode": "rw",
                }
            },
        )

        logger.debug(f"Container {self.container.id} started")

        self._copy_source()

        return self.container

    @log_func
    def _stop_container(self):
        if hasattr(self, "container") and self.container:
            try:
                self.container.stop()
                self.container.remove()
                logger.debug(f"Container {self.container.id} stopped and removed")
            except Exception as e:
                logger.warning(
                    f"Failed to stop/remove container {self.container.id}: {e}"
                )
            finally:
                self.container = None

    def __enter__(self):
        self.container = self._start_container()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._stop_container()


class OssFuzzDebugDocker:
    def __init__(
        self,
        project_name: str,
        project_language: str,
        source_dir: Path,
    ):
        self.project_name = project_name
        self.project_language = project_language
        project_yaml_path = OSS_FUZZ_DIR / "projects" / project_name / "project.yaml"
        self.proj_yaml = yaml.safe_load(project_yaml_path.read_text())
        self.source_dir = source_dir
        self.container: Container | None = None
        self.image_name = f"aixcc-afc/{self.project_name}-sarif-debug"

        self.client = from_env()
        self._build_image()

    def exec(
        self,
        cmd: str,
        env: dict | None = None,
        work_dir: str | None = None,
        isPrint: int = 1,
    ) -> bool:
        if env is None:
            env = dict()

        for container_env in self.container.attrs["Config"]["Env"]:
            if container_env.startswith("PATH="):
                env["PATH"] = container_env.split("=")[1]
                break

        result = self.container.exec_run(
            cmd, stdout=True, stderr=True, environment=env, workdir=work_dir
        )
        if isPrint:
            log(f"Command output: {result.output.decode()}")
        if result.exit_code != 0:
            error(f"Command failed with exit code: {result.exit_code}")
            raise DockerExecError

        return result

    @log_func
    def _build_image(self):
        env = [f'ENV {k} "{v}"' for k, v in self._get_debug_build_env().items()]

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            dockerfile_path = tmp_path / "Dockerfile"
            dockerfile_content = (
                """
"""
                + f"FROM aixcc-afc/{self.project_name}-sarif-codeql"
                + """

"""
                + "\n".join(env)
                + """
"""
            )
            dockerfile_path.write_text(dockerfile_content)

            (tmp_path / "llm-poc-gen").mkdir(parents=True, exist_ok=True)
            if os.environ.get("RUN_GDB_SH_PATH") is None:
                shutil.copy("llm-poc-gen/run_gdb.sh", tmp_path / "run_gdb.sh")
            else:
                shutil.copy(os.environ["RUN_GDB_SH_PATH"], tmp_path / "run_gdb.sh")

            subprocess.run(
                f"docker build --pull=false -t aixcc-afc/{self.project_name}-sarif-debug -f {dockerfile_path} {tmp_path}",
                shell=True,
                check=True,
            )

            log(f"[+] Debugger image built: {self.image_name}")

    def _get_debug_build_env(self):
        OSS_FUZZ_DEFAULT_CFLAGS = (
            "-O1 -fno-omit-frame-pointer -gline-tables-only "
            "-Wno-error=enum-constexpr-conversion "
            "-Wno-error=incompatible-function-pointer-types "
            "-Wno-error=int-conversion -Wno-error=deprecated-declarations "
            "-Wno-error=implicit-function-declaration -Wno-error=implicit-int "
            "-Wno-error=vla-cxx-extension "
            "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION "
            "-fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link"
        )
        OSS_FUZZ_DEFAULT_CXXFLAGS = f"{OSS_FUZZ_DEFAULT_CFLAGS} -stdlib=c++"

        env = dict(DOCKER_BUILD_ENV)
        env["CFLAGS"] = OSS_FUZZ_DEFAULT_CFLAGS.replace("-O1 ", "-O0 ")
        env["CXXFLAGS"] = OSS_FUZZ_DEFAULT_CXXFLAGS.replace("-O1 ", "-O0 ")
        env["CFLAGS"] += " -g -fno-inline"
        env["CXXFLAGS"] += " -g -fno-inline"

        return env

    def _copy_source(self):
        tarstream = io.BytesIO()
        with tarfile.open(fileobj=tarstream, mode="w") as tar:
            tar.add(self.source_dir.absolute(), arcname=".")
        tarstream.seek(0)

        work_dir = self._get_workdir()

        self.exec(f"rm -rf {work_dir}", work_dir="/")
        self.exec(f"mkdir -p {work_dir}", work_dir="/")

        self.container.put_archive(work_dir, tarstream)

    def _get_workdir(self):
        return self.exec("pwd").output.decode().strip()

    def _start_container(self) -> Container:
        build_env = self._get_debug_build_env()
        container_name = f"{self.project_name.replace('/', '-')}-sarif-debug"

        try:
            existing = self.client.containers.get(container_name)
            existing.stop()
            existing.remove()
        except docker.errors.NotFound:
            pass

        self.container = self.client.containers.run(
            name=container_name,
            image=self.image_name,
            command=["/bin/bash"],
            detach=True,
            tty=True,
            stdin_open=True,
            environment=build_env,
            privileged=True,
            security_opt=["seccomp=unconfined"],
            volumes={
                str(DEBUG_DIR.absolute()): {
                    "bind": "/out",
                    "mode": "rw",
                },
            },
        )

        logger.debug(f"Debugger container {self.container.id} started")

        self._copy_source()

        return self.container

    @log_func
    def _stop_container(self):
        if hasattr(self, "container") and self.container:
            try:
                self.container.stop()
                self.container.remove()
                logger.debug(f"Container {self.container.id} stopped and removed")
            except Exception as e:
                logger.warning(
                    f"Failed to stop/remove container {self.container.id}: {e}"
                )
            finally:
                self.container = None

    def __enter__(self):
        self.container = self._start_container()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._stop_container()


@log_func
def build_sootup(oss_fuzz_docker: OssFuzzDocker):
    copy_jars_to_out(oss_fuzz_docker)  # TODO: for testing
    # /usr/lib/jvm/java-17-openjdk-amd64/bin/java -jar /opt/sootup/target/sootup-reachability.jar get-all-reachable-methods --output-dir /out/sootup --dump-call-graph /out/jars
    oss_fuzz_docker.exec(f"mkdir -p /out/sootup")
    # attach_to_container(oss_fuzz_docker.container.id)
    cmd = " ".join(
        [
            "/usr/lib/jvm/java-17-openjdk-amd64/bin/java",
            "-jar",
            "/opt/sootup/target/sootup-reachability.jar",
            "get-all-reachable-methods",
            "--output-dir",
            "/out/sootup",
            "--dump-call-graph",
            "/out/jars",
        ]
    )
    oss_fuzz_docker.exec(cmd)


@log_func
def copy_jars_to_out(oss_fuzz_docker: OssFuzzDocker):
    oss_fuzz_docker.exec(f"mkdir -p /out/jars")
    oss_fuzz_docker.exec(f"find /out -name *.jar -exec cp \\{{\\}} /out/jars/ \\;")


@log_func
def build_codeql_db(oss_fuzz_docker: OssFuzzDocker, language: str):
    if language == "jvm":
        language = "java"

    build_cmd_candidates = ["compile", "bash -c 'bash -eux /src/build.sh'"]

    db_path = "/out/codeql"

    if (OUT_DIR / "codeql").exists():
        try:
            shutil.rmtree(OUT_DIR / "codeql")
        except Exception as e:
            logger.warning("Please remove the codeql db manually")
            raise e

    for build_cmd in build_cmd_candidates:
        cmd = " ".join(
            [
                "codeql",
                "database",
                "create",
                "--language=" + language,
                "--source-root=.",
                "--threads=" + CODEQL_THREADS,
                "--command=" + build_cmd,
                db_path,
            ]
        )

        try:
            oss_fuzz_docker.exec(cmd)
        except DockerExecError as e:
            logger.warning(f"Failed to build codeql db with command: {build_cmd}")
            logger.warning(f"Error: {e}")
            oss_fuzz_docker.exec(f"rm -rf {db_path}")
        else:
            break


def _get_env_dict(oss_fuzz_docker: OssFuzzDocker):
    env_vars = oss_fuzz_docker.exec("env").output.decode().strip().split("\n")
    env_dict = {}
    for var in env_vars:
        if "=" in var:
            key, value = var.split("=", 1)
            env_dict[key] = value

    return env_dict


@log_func
def _svf_build_cp(oss_fuzz_docker: OssFuzzDocker, env_dict: dict):
    cmd = "compile"

    env_dict.update(
        {
            "CC": "gclang",
            "CXX": "gclang++",
            "CFLAGS": env_dict["CFLAGS"].replace("-O1 ", "-O0 "),
            "CXXFLAGS": env_dict["CXXFLAGS"].replace("-O1 ", "-O0 "),
        }
    )

    oss_fuzz_docker.exec(cmd, env=env_dict)


@log_func
def _svf_extract_bc(oss_fuzz_docker: OssFuzzDocker):
    for harness in HARNESS_NAMES.split(":"):
        harness_path = f"/out/{harness}"

        cmd = " ".join(
            [
                "get-bc",
                harness_path,
            ]
        )

        oss_fuzz_docker.exec(cmd)


def _handle_svf_exec_result(
    oss_fuzz_docker: OssFuzzDocker, cmd: str, harness: str, operation: str
):
    try:
        result = oss_fuzz_docker.exec(cmd)
        log(f"Successfully completed {operation} for harness: {harness}")
        return True
    except DockerExecError as e:
        # Check if it's a timeout by examining the command output
        try:
            # Try to get the last command output to check for timeout message
            check_result = oss_fuzz_docker.exec(
                "echo 'Checking previous command result'", isPrint=0
            )
            error(f"Failed to complete {operation} for harness: {harness}")
            error(
                f"This might be due to timeout or other issues. Continuing with next step..."
            )
            return False
        except:
            error(
                f"Failed to complete {operation} for harness: {harness}. Continuing..."
            )
            return False
    except Exception as e:
        error(f"Unexpected error during {operation} for harness: {harness}: {str(e)}")
        return False


@log_func
def _svf_create_callgraph(oss_fuzz_docker: OssFuzzDocker):
    for harness in HARNESS_NAMES.split(":"):
        harness_path = f"/out/{harness}"

        # Check if the call graph already exists
        call_graph_path = f"/out/SVF/call_graph_{SVF_MODE}_{harness}.dot"

        if SVF_MODE == "ander":
            cmd = " ".join(
                [
                    "bash -c",
                    f"'ulimit -v {ULIMIT_MEM} && wpa -ander -ander-time-limit={WPA_TIMEOUT} -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path}'",
                ]
            )
            success = _handle_svf_exec_result(
                oss_fuzz_docker, cmd, harness, "ander analysis"
            )
            if not success:
                cmd = " ".join(
                    [
                        "bash -c",
                        f"'ulimit -v {ULIMIT_MEM} && wpa -steens -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path}'",
                    ]
                )

                success = _handle_svf_exec_result(
                    oss_fuzz_docker, cmd, harness, "steens analysis"
                )
                if not success:
                    log(
                        f"Steens analysis failed for {harness}, but continuing with next harness..."
                    )
                    continue

        else:
            cmd = " ".join(
                [
                    "bash -c",
                    f"'ulimit -v {ULIMIT_MEM} && wpa -{SVF_MODE} -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path}'",
                ]
            )
            success = _handle_svf_exec_result(
                oss_fuzz_docker, cmd, harness, f"{SVF_MODE} analysis"
            )
            if not success:
                log(
                    f"{SVF_MODE} analysis failed/timed out for {harness}, but continuing with next harness..."
                )
                continue

        # Add source filenames to function nodes in the DOT file
        _svf_add_source_filenames_to_dot(oss_fuzz_docker, call_graph_path, harness_path)


@log_func
def _svf_add_source_filenames_to_dot(
    oss_fuzz_docker: OssFuzzDocker, dot_file_path, bc_file_path
):
    check_cmd = "which llvm-dis-18"
    result = oss_fuzz_docker.exec(check_cmd)
    llvm_dis_cmd = "llvm-dis-18" if result.exit_code == 0 else "llvm-dis"

    output_ll_path = f"{bc_file_path}.ll"
    cmd = f'bash -c "{llvm_dis_cmd} {bc_file_path}.bc -o {output_ll_path}"'

    result = oss_fuzz_docker.exec(cmd)
    if result.exit_code != 0:
        logger.warning(f"Failed to generate LLVM IR from {bc_file_path}.bc")
        return

    lines = oss_fuzz_docker._read_file_from_container(output_ll_path)

    dbg_to_func = {}
    sub_to_file = {}
    file_map = {}

    for line in lines:
        m = re.search(r"define\s+.*@([^( ]+)\s*\(.*\)\s+.*!dbg !(\d+)", line)
        if m:
            func_name, dbg_id = m.groups()
            dbg_to_func[dbg_id] = func_name

    for line in lines:
        m = re.search(r"!(\d+) = distinct !DISubprogram\(.*file: !(\d+)", line)
        if m:
            dbg_id, file_id = m.groups()
            sub_to_file[dbg_id] = file_id

    for line in lines:
        m = re.search(
            r'!(\d+) = !DIFile\(filename: "([^"]+)", directory: "([^"]+)"', line
        )
        if m:
            file_id, fname, fdir = m.groups()
            file_map[file_id] = os.path.join(fdir, fname)

    func_to_file = {}
    for dbg_id, func_name in dbg_to_func.items():
        file_id = sub_to_file.get(dbg_id)
        file_path = file_map.get(file_id)
        if file_path:
            func_to_file[func_name] = file_path

    # if "LLVMFuzzerTestOneInput" in func_to_file:
    #     logger.info(f"LLVMFuzzerTestOneInput: {func_to_file['LLVMFuzzerTestOneInput']}")
    # else:
    #     logger.info("LLVMFuzzerTestOneInput not found")

    cmd = f"cat {dot_file_path}"
    result = oss_fuzz_docker.exec(cmd, isPrint=0)
    if result.exit_code != 0:
        return

    dot_content = result.output.decode()

    def add_file_name_to_node(match):
        label = match.group(0)
        fun_match = re.search(r"{fun: ([^}]+)}", label)
        if fun_match:
            func = fun_match.group(1).replace("\\", "")
            file_name = func_to_file.get(func)
            if file_name:
                label = label[:-1] + f', file_name="{file_name}"]'
                return label
        return label

    modified_dot = re.sub(
        r'\[.*?label="[^"]*\{fun: [^}]*\}[^"]*".*?\]',
        add_file_name_to_node,
        dot_content,
    )

    with open("/tmp/modified.dot", "w") as f:
        f.write(modified_dot)

    oss_fuzz_docker._copy_file_to_container("/tmp/modified.dot", dot_file_path)


@log_func
def build_SVF_dot(oss_fuzz_docker: OssFuzzDocker, env_dict: dict):
    try:
        _svf_build_cp(oss_fuzz_docker, env_dict)
        _svf_extract_bc(oss_fuzz_docker)
        # attach_to_container(oss_fuzz_docker.container.id)
        _svf_create_callgraph(oss_fuzz_docker)
    except Exception as e:
        error(f"Error in build_SVF_dot: {e}")
        error(f"Do not use SVF for {PROJECT_NAME}")
        (BUILD_SHARED_DIR / "AUX_FAILED").touch()


@log_func
def _svf_extract_bc_single_harness(harness: str, container_id: str):
    client = from_env()

    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound:
        error(f"Container {container_id} not found for harness {harness}")
        return harness, 1

    harness_path = f"/out/{harness}"

    cmd = " ".join(
        [
            "get-bc",
            harness_path,
        ]
    )

    log(f"Extracting bytecode for harness: {harness}")

    env_dict = {}
    for container_env in container.attrs["Config"]["Env"]:
        if "=" in container_env:
            key, value = container_env.split("=", 1)
            env_dict[key] = value

    result = container.exec_run(cmd, stdout=True, stderr=True, environment=env_dict)

    if result.exit_code == 0:
        log(f"Successfully extracted bytecode for harness: {harness}")
    else:
        error(f"Failed to extract bytecode for harness: {harness}")
        error(f"Command output: {result.output.decode()}")

    return harness, result.exit_code


@log_func
def _svf_create_callgraph_single_harness(harness: str, container_id: str):
    client = from_env()

    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound:
        error(f"Container {container_id} not found for harness {harness}")
        return harness, 1

    harness_path = f"/out/{harness}"
    call_graph_path = f"/out/SVF/call_graph_{SVF_MODE}_{harness}.dot"

    if SVF_MODE == "ander":
        cmd = " ".join(
            [
                "bash -c",
                f"'mkdir -p /out/SVF/{harness} && pushd /out/SVF/{harness} && ulimit -v {ULIMIT_MEM} && wpa -ander -ander-time-limit={WPA_TIMEOUT} -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path} && popd'",
            ]
        )
    else:
        cmd = " ".join(
            [
                "bash -c",
                f"'mkdir -p /out/SVF/{harness} && pushd /out/SVF/{harness} && ulimit -v {ULIMIT_MEM} && wpa -{SVF_MODE} -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path} && popd'",
            ]
        )

    log(f"Creating call graph for harness: {harness} using {SVF_MODE} mode")

    env_dict = {}
    for container_env in container.attrs["Config"]["Env"]:
        if "=" in container_env:
            key, value = container_env.split("=", 1)
            env_dict[key] = value

    result = container.exec_run(cmd, stdout=True, stderr=True, environment=env_dict)

    if result.exit_code == 0:
        _svf_add_source_filenames_to_dot_multiprocess(
            container, call_graph_path, harness_path
        )
        log(f"Successfully created call graph for harness: {harness}")
    else:
        # Check if it's a timeout or other failure
        output = result.output.decode()
        if "time limit reached" in output.lower() or "timeout" in output.lower():
            error(
                f"Timeout occurred for harness: {harness}. This is expected for complex analyses."
            )
        else:
            error(f"Failed to create call graph for harness: {harness}")
            error(f"Command output: {output}")

        # Return exit code 0 for timeout cases to continue processing other harnesses
        if "time limit reached" in output.lower():
            log(f"Treating timeout as non-fatal error for harness: {harness}")
            return harness, 0

    return harness, result.exit_code


@log_func
def _svf_extract_bc_parallel(oss_fuzz_docker: OssFuzzDocker, max_workers: int = None):
    harnesses = HARNESS_NAMES.split(":")

    if max_workers is None:
        max_workers = min(len(harnesses), 4)

    log(
        f"Extracting bytecode for {len(harnesses)} harnesses using {max_workers} processes"
    )

    container_id = oss_fuzz_docker.container.id

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_harness = {
            executor.submit(
                _svf_extract_bc_single_harness, harness, container_id
            ): harness
            for harness in harnesses
        }

        failed_harnesses = []
        for future in as_completed(future_to_harness):
            harness = future_to_harness[future]
            try:
                harness_name, exit_code = future.result()
                if exit_code != 0:
                    failed_harnesses.append(harness_name)
            except Exception as exc:
                error(f"Harness {harness} generated an exception: {exc}")
                failed_harnesses.append(harness)

    if failed_harnesses:
        error(
            f"Failed to extract bytecode for harnesses: {', '.join(failed_harnesses)}"
        )
        return False

    log("Successfully extracted bytecode for all harnesses")
    return True


@log_func
def _svf_create_callgraph_parallel(
    oss_fuzz_docker: OssFuzzDocker, max_workers: int = None
):
    harnesses = HARNESS_NAMES.split(":")

    if max_workers is None:
        max_workers = min(len(harnesses), 4)

    log(
        f"Creating call graphs for {len(harnesses)} harnesses using {max_workers} processes"
    )

    container_id = oss_fuzz_docker.container.id

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_harness = {
            executor.submit(
                _svf_create_callgraph_single_harness, harness, container_id
            ): harness
            for harness in harnesses
        }

        failed_harnesses = []
        for future in as_completed(future_to_harness):
            harness = future_to_harness[future]
            try:
                harness_name, exit_code = future.result()
                if exit_code != 0:
                    failed_harnesses.append(harness_name)
            except Exception as exc:
                error(f"Harness {harness} generated an exception: {exc}")
                failed_harnesses.append(harness)

    if failed_harnesses:
        error(
            f"Failed to create call graphs for harnesses: {', '.join(failed_harnesses)}"
        )
        return False

    log("Successfully created call graphs for all harnesses")
    return True


@log_func
def build_SVF_dot_parallel(
    oss_fuzz_docker: OssFuzzDocker, env_dict: dict, max_workers: int = None
):
    try:
        _svf_build_cp(oss_fuzz_docker, env_dict)

        if not _svf_extract_bc_parallel(oss_fuzz_docker, max_workers):
            raise Exception("Failed to extract bytecode for some harnesses")

        if not _svf_create_callgraph_parallel(oss_fuzz_docker, max_workers):
            raise Exception("Failed to create call graphs for some harnesses")

    except Exception as e:
        error(f"Error in build_SVF_dot_parallel: {e}")
        error(f"Do not use SVF for {PROJECT_NAME}")
        (BUILD_SHARED_DIR / "AUX_FAILED").touch()


@log_func
def _create_cpg(oss_fuzz_docker: OssFuzzDocker):
    cpg_path = "/out/joern/cpg.bin"
    timeout = CPG_BUILD_TIMEOUT

    match PROJECT_LANGUAGE:
        case "c":
            cmd = " ".join(
                [
                    "/opt/joern/joern-cli/frontends/c2cpg/target/universal/stage/bin/c2cpg",
                    "/src",
                    "--exclude=/src/aflplusplus",
                    "--exclude=/src/fuzztest",
                    "--exclude=/src/honggfuzz",
                    "--exclude=/src/libfuzzer",
                    "--with-include-auto-discovery",
                    "-J-Xmx12g",
                    "--output=" + cpg_path,
                ]
            )
            oss_fuzz_docker.exec(cmd, timeout=timeout)
        case "cpp":
            cmd = " ".join(
                [
                    "/opt/joern/joern-cli/frontends/c2cpg/target/universal/stage/bin/c2cpg",
                    "/src",
                    "--exclude=/src/aflplusplus",
                    "--exclude=/src/fuzztest",
                    "--exclude=/src/honggfuzz",
                    "--exclude=/src/libfuzzer",
                    "--with-include-auto-discovery",
                    "-J-Xmx12g",
                    "--output=" + cpg_path,
                ]
            )
            oss_fuzz_docker.exec(cmd, timeout=timeout)
        case "jvm":
            cmd = " ".join(
                [
                    "/opt/joern/joern-cli/frontends/javasrc2cpg/target/universal/stage/bin/javasrc2cpg",
                    "/src",
                    "--exclude=/src/aflplusplus",
                    "--exclude=/src/fuzztest",
                    "--exclude=/src/honggfuzz",
                    "--exclude=/src/libfuzzer",
                    "-J-Xmx12g",
                    "--output=" + cpg_path,
                ]
            )
            oss_fuzz_docker.exec(
                cmd, env={"JAVA_HOME": "/usr/lib/jvm/java-17-openjdk-amd64"}
            )
        case _:
            raise ValueError(f"Unsupported language: {PROJECT_LANGUAGE}")


@log_func
def build_joern_cpg(oss_fuzz_docker: OssFuzzDocker):
    _create_cpg(oss_fuzz_docker)


@log_func
def copy_cpg_src(oss_fuzz_docker: OssFuzzDocker):
    oss_fuzz_docker._copy_files_from_container("/src", CPG_SRC_DIR)


@log_func
def prepare_debug(oss_fuzz_debug_docker: OssFuzzDebugDocker):
    cmd = "compile"
    oss_fuzz_debug_docker.exec(cmd)


@log_func
def _archive_and_copy_dir(
    dir: Path, tar_path: Path, exclude_patterns: Optional[list[str]] = None
):
    shared_path = BUILD_SHARED_DIR / tar_path.name
    if not _archive_dir_shell(dir, tar_path, exclude_patterns=exclude_patterns):
        error(f"Failed to archive {dir} output.")
    shutil.copy(tar_path, shared_path)
    checksum = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    with open(shared_path.with_suffix(".sha256"), "w") as f:
        f.write(checksum)


@log_func
def copy_codeql_out_to_shared_build():
    _archive_and_copy_dir(CODEQL_OUT_DIR, OUT_DIR / "codeql.tar.gz")

    (BUILD_SHARED_DIR / "CODEQL_DONE").touch()


@log_func
def copy_essential_out_to_shared_build():
    # _archive_and_copy_dir(CODEQL_OUT_DIR, OUT_DIR / "codeql.tar.gz")
    _archive_and_copy_dir(JOERN_OUT_DIR, OUT_DIR / "joern.tar.gz")

    (BUILD_SHARED_DIR / "ESSENTIAL_DONE").touch()


@log_func
def copy_poc_gen_out_to_shared_build():
    _archive_and_copy_dir(CPG_SRC_DIR, OUT_DIR / "cpg_src.tar.gz")
    _archive_and_copy_dir(DEBUG_DIR, OUT_DIR / "debug.tar.gz")

    (BUILD_SHARED_DIR / "POC_GEN_DONE").touch()


@log_func
def copy_aux_out_to_shared_build():
    _archive_and_copy_dir(SVF_OUT_DIR, OUT_DIR / "SVF.tar.gz")

    if PROJECT_LANGUAGE == "jvm":
        exclude_patterns = [
            "SVF.tar.gz",
            "codeql.tar.gz",
            "joern.tar.gz",
            "SVF",
            "codeql",
            "joern",
        ]
        _archive_and_copy_dir(
            OUT_DIR,
            SOURCE_DIR / "out.tar.gz",
            exclude_patterns=exclude_patterns,
        )

    (BUILD_SHARED_DIR / "AUX_DONE").touch()


@log_func
def _svf_add_source_filenames_to_dot_multiprocess(
    container, dot_file_path, bc_file_path
):
    env_dict = {}
    for container_env in container.attrs["Config"]["Env"]:
        if "=" in container_env:
            key, value = container_env.split("=", 1)
            env_dict[key] = value

    check_cmd = "which llvm-dis-18"
    result = container.exec_run(
        check_cmd, stdout=True, stderr=True, environment=env_dict
    )
    llvm_dis_cmd = "llvm-dis-18" if result.exit_code == 0 else "llvm-dis"

    output_ll_path = f"{bc_file_path}.ll"
    cmd = f'bash -c "{llvm_dis_cmd} {bc_file_path}.bc -o {output_ll_path}"'

    result = container.exec_run(cmd, stdout=True, stderr=True, environment=env_dict)
    if result.exit_code != 0:
        logger.warning(f"Failed to generate LLVM IR from {bc_file_path}.bc")
        return

    with tempfile.TemporaryDirectory() as temp_dir:
        stream, stat = container.get_archive(output_ll_path)
        file_bytes = b"".join(chunk for chunk in stream)

        with tarfile.open(fileobj=io.BytesIO(file_bytes)) as tar:
            tar.extractall(path=temp_dir)

        extracted_file_path = os.path.join(temp_dir, os.path.basename(output_ll_path))
        with open(extracted_file_path, "r") as f:
            lines = f.readlines()

    dbg_to_func = {}
    sub_to_file = {}
    file_map = {}

    for line in lines:
        m = re.search(r"define\s+.*@([^( ]+)\s*\(.*\)\s+.*!dbg !(\d+)", line)
        if m:
            func_name, dbg_id = m.groups()
            dbg_to_func[dbg_id] = func_name

    for line in lines:
        m = re.search(r"!(\d+) = distinct !DISubprogram\(.*file: !(\d+)", line)
        if m:
            dbg_id, file_id = m.groups()
            sub_to_file[dbg_id] = file_id

    for line in lines:
        m = re.search(
            r'!(\d+) = !DIFile\(filename: "([^"]+)", directory: "([^"]+)"', line
        )
        if m:
            file_id, fname, fdir = m.groups()
            file_map[file_id] = os.path.join(fdir, fname)

    func_to_file = {}
    for dbg_id, func_name in dbg_to_func.items():
        file_id = sub_to_file.get(dbg_id)
        file_path = file_map.get(file_id)
        if file_path:
            func_to_file[func_name] = file_path

    cmd = f"cat {dot_file_path}"
    result = container.exec_run(cmd, stdout=True, stderr=True, environment=env_dict)
    if result.exit_code != 0:
        return

    dot_content = result.output.decode()

    def add_file_name_to_node(match):
        label = match.group(0)
        fun_match = re.search(r"{fun: ([^}]+)}", label)
        if fun_match:
            func = fun_match.group(1).replace("\\", "")
            file_name = func_to_file.get(func)
            if file_name:
                label = label[:-1] + f', file_name="{file_name}"]'
                return label
        return label

    modified_dot = re.sub(
        r'\[.*?label="[^"]*\{fun: [^}]*\}[^"]*".*?\]',
        add_file_name_to_node,
        dot_content,
    )

    with open("/tmp/modified.dot", "w") as f:
        f.write(modified_dot)

    container_dir = os.path.dirname(dot_file_path)
    container_filename = os.path.basename(dot_file_path)

    tarstream = io.BytesIO()
    with tarfile.open(fileobj=tarstream, mode="w") as tar:
        tar.add("/tmp/modified.dot", arcname=container_filename)
    tarstream.seek(0)

    container.put_archive(container_dir, tarstream)


def clean_up():
    for dir in [SOURCE_DIR, OUT_DIR]:
        shutil.rmtree(dir, ignore_errors=True)


@log_func
def attach_to_container(container_name=None):
    client = from_env()

    if container_name is None:
        containers = client.containers.list(all=True)
        target_containers = [
            c
            for c in containers
            if c.name and (c.name.startswith("sootup_") or c.name.startswith("svf_"))
        ]

        if not target_containers:
            logger.info("No SootUp or SVF containers found.")
            return

        print("\nAvailable SootUp or SVF containers:")
        for i, container in enumerate(target_containers):
            print(
                f"{i+1}. {container.name} (ID: {container.id}, Status: {container.status})"
            )

        try:
            choice = int(
                input(
                    "\nEnter the number of the container to attach to (0 to cancel): "
                )
            )
            if choice == 0:
                return
            if choice < 1 or choice > len(target_containers):
                logger.error("Invalid choice.")
                return

            container = target_containers[choice - 1]
        except ValueError:
            logger.error("Invalid input. Please enter a number.")
            return
    else:
        try:
            container = client.containers.get(container_name)
        except Exception as e:
            logger.error(f"Container '{container_name}' not found: {e}")
            return

    if container.status != "running":
        logger.info(f"Container {container.name} is not running. Starting it...")
        try:
            container.start()
            logger.info(f"Container {container.name} started.")
        except Exception as e:
            logger.error(f"Failed to start container: {e}")
            return

    logger.info(f"Attaching to container {container.name} (ID: {container.id})...")
    logger.info("Type 'exit' to leave the container.")

    try:
        subprocess.run(["docker", "exec", "-it", container.id, "/bin/bash"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to attach to container: {e}")
    except KeyboardInterrupt:
        logger.info("Detached from container.")


if __name__ == "__main__":
    # clean_up()

    log("Starting build...")

    source_dir = setup_challenge_project()
    setup_docker_volumes()
    with OssFuzzDocker(
        PROJECT_NAME, PROJECT_LANGUAGE, source_dir, codeql=True
    ) as oss_fuzz_docker:
        # CODEQL-DB
        build_codeql_db(oss_fuzz_docker, PROJECT_LANGUAGE)
        copy_codeql_out_to_shared_build()
        oss_fuzz_docker.download_source(COMPILED_SRC_DIR)

    with OssFuzzDocker(
        PROJECT_NAME, PROJECT_LANGUAGE, COMPILED_SRC_DIR
    ) as oss_fuzz_docker:
        # JOERN-CPG
        try:
            build_joern_cpg(oss_fuzz_docker)
        except Exception as e:
            error(f"Error in joern-cpg build: {e}")
            error(f"Do not use joern-cpg for {PROJECT_NAME}")
            (BUILD_SHARED_DIR / "JOERN_CPG_FAILED").touch()
        copy_essential_out_to_shared_build()

        if PROJECT_LANGUAGE in ["c", "cpp", "c++"]:
            with OssFuzzDebugDocker(
                PROJECT_NAME, PROJECT_LANGUAGE, source_dir
            ) as oss_fuzz_debug_docker:
                # LLM-POC-GEN
                try:
                    copy_cpg_src(oss_fuzz_docker)
                    prepare_debug(oss_fuzz_debug_docker)
                    copy_poc_gen_out_to_shared_build()
                except Exception as e:
                    error(f"Error in llm-poc-gen build: {e}")
                    error(f"Do not use llm-poc-gen for {PROJECT_NAME}")
                    (BUILD_SHARED_DIR / "POC_GEN_FAILED").touch()

            # SVF
            with OssFuzzDocker(
                PROJECT_NAME, PROJECT_LANGUAGE, source_dir
            ) as oss_fuzz_docker:
                env_dict = _get_env_dict(oss_fuzz_docker)
                start = time.time()
                if SVF_PARALLEL:
                    log(
                        f"Using parallel SVF multiprocessing with {SVF_MAX_WORKERS} max workers"
                    )
                    build_SVF_dot_parallel(oss_fuzz_docker, env_dict, SVF_MAX_WORKERS)
                else:
                    log("Using sequential SVF processing")
                    build_SVF_dot(oss_fuzz_docker, env_dict)
                end = time.time()
                log(f"SVF processing took {end - start} seconds")
        else:
            log("Nothing to build AUX for jvm projects")

        copy_aux_out_to_shared_build()

    log("All done!")
