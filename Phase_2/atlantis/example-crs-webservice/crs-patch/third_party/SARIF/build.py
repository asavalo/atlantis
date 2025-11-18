import functools
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Optional

import docker
import yaml
from docker import from_env
from docker.models.containers import Container
from loguru import logger

OSS_FUZZ_DIR = Path(os.environ["OSS_FUZZ_DIR"])
OSS_FUZZ_PROJECTS_DIR = OSS_FUZZ_DIR / "projects"
OSS_FUZZ_HELPER = str(OSS_FUZZ_DIR / "infra/helper.py")

SOURCE_DIR = Path(os.environ["SOURCE_DIR"])
TARBALL_DIR = Path(os.environ["TARBALL_DIR"])

REGISTRY = os.getenv("REGISTRY", "ghcr.io/team-atlanta")
SARIF_BASE_IMAGE = REGISTRY + "/crs-sarif"
# SARIF_CRS_IMAGE = SARIF_BASE_IMAGE + "/crs-sarif"
SARIF_BUILDER_C_IMAGE = SARIF_BASE_IMAGE + "/sarif-builder"
SARIF_BUILDER_JVM_IMAGE = SARIF_BASE_IMAGE + "/sarif-builder-jvm"
IMAGE_VERSION = os.getenv("IMAGE_VERSION", "latest")

PROJECT_NAME = os.getenv("PROJECT_NAME", "mock-c")
PROJECT_LANGUAGE = os.getenv("PROJECT_LANGUAGE", "c")
HARNESS_NAMES = os.getenv("HARNESS_NAMES", "ossfuzz-1:ossfuzz-2")

IS_BENCHMARK = os.getenv("IS_BENCHMARK", "True")
CODEQL_THREADS = os.getenv("CODEQL_THREADS", "16")

SARIF_BUILDER_IMAGE = SARIF_BUILDER_C_IMAGE
if PROJECT_LANGUAGE == "jvm":
    SARIF_BUILDER_IMAGE = SARIF_BUILDER_JVM_IMAGE

# ORIGINAL_BUILD_DIR = Path(os.getenv("ORIGINAL_BUILD_DIR"))

OUT_DIR = Path(
    os.getenv("OUT_DIR")
)  # Shared out dir. CRS-SARIF will copy built files here

SVF_OUT_DIR = OUT_DIR / "SVF"
CODEQL_OUT_DIR = OUT_DIR / "codeql"
JOERN_OUT_DIR = OUT_DIR / "joern"
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


def log(message: str):
    logger.info(f"[SARIF-BUILDER] {message}")


def error(message: str):
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
    repo_tarfile = tarfile_dir / "repo.tar.gz"
    if not repo_tarfile.exists():
        raise ValueError(f"Repo tarfile {repo_tarfile} does not exist")

    diff_tarfile = tarfile_dir / "diff.tar.gz"
    if not diff_tarfile.exists():
        diff_tarfile = None

    if (tarfile_dir / "oss-fuzz.tar.gz").exists():
        oss_fuzz_tarfile = tarfile_dir / "oss-fuzz.tar.gz"
        _extract_tarfile(oss_fuzz_tarfile, output_dir)

    return setup_challenge_project_from_tarfiles(repo_tarfile, output_dir, diff_tarfile)


@log_func
def setup_challenge_project_from_tarfiles(
    source_tarfile: Path,
    output_dir: Path = SOURCE_DIR,
    diff_tarfile: Optional[Path] = None,
) -> Path:
    # Extract the project source tarball
    source_dir = _extract_repo_tarfile(source_tarfile, output_dir)

    subprocess.check_call(f"git init {source_dir}", shell=True)
    subprocess.check_call(
        f"git config --global --add safe.dir {source_dir}", shell=True
    )
    subprocess.check_call("git add . -f", cwd=source_dir, shell=True)
    subprocess.check_call("git commit -m 'Initial commit'", cwd=source_dir, shell=True)

    if diff_tarfile is not None:
        # Extract the diff tarball
        _extract_tarfile(diff_tarfile, output_dir)

        diff_file = Path("../diff/ref.diff")
        subprocess.check_call(
            f"git apply --index {diff_file}", cwd=source_dir, shell=True
        )
        subprocess.check_call(
            "git commit -m 'Update changes'", cwd=source_dir, shell=True
        )
    subprocess.check_call("rm -rf .git", cwd=source_dir, shell=True)

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


def _rewrite_dockerfile(dockerfile: Path):
    prev = dockerfile.read_text()
    if "sarif-builder" not in prev:
        new = prev
        base_image = __extract_base_image(prev)
        base_url = base_image.split(":")[0]
        new_url = f"{REGISTRY}/crs-sarif/sarif-builder"
        if base_url.endswith("-jvm"):
            new_url += "-jvm"
        new_url += f":{IMAGE_VERSION}"
        new = new.replace(base_image, new_url)
        dockerfile.write_text(new)


def _modify_dockerfile(target_project_dir: Path):
    dockerfile = target_project_dir / "Dockerfile"
    log(dockerfile)
    _rewrite_dockerfile(dockerfile)


@log_func
def setup_oss_fuzz_projects(output_dir: Path = SOURCE_DIR):
    projects_dir = output_dir / "fuzz-tooling" / "projects"
    target_dir = OSS_FUZZ_DIR / "projects"
    subprocess.run(f"rsync -a --delete {projects_dir}/ {target_dir}", shell=True)

    _modify_dockerfile(target_dir / PROJECT_NAME)


def _extract_repo_tarfile(tar_path: Path, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    members = _extract_tarfile(tar_path, output_dir)

    return output_dir / members[0].name


def _extract_tarfile(tar_path: Path, output_dir: Path):
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(output_dir)
        return tar.getmembers()


@log_func
def _archive_dir_shell(dir: Path, tar_path: Path):
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
        "-C",
        str(source_dir_parent.resolve()),
        source_dir_name,
    ]

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
    ):
        self.project_name = project_name
        self.project_language = project_language
        project_yaml_path = OSS_FUZZ_DIR / "projects" / project_name / "project.yaml"
        self.proj_yaml = yaml.safe_load(project_yaml_path.read_text())
        self.source_dir = source_dir
        self.container: Container | None = None
        self.image_name = f"aixcc-afc/{self.project_name}-sarif"

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
        # subprocess.run(
        #     # f"python3 {OSS_FUZZ_HELPER} build_fuzzers {self.project_name} {self.source_dir.absolute()}",
        #     f"python3 {OSS_FUZZ_HELPER} build_image {self.project_name} --pull",
        #     shell=True,
        # )

        docker_proj_path = OSS_FUZZ_DIR / "projects" / self.project_name
        dockerfile_path = docker_proj_path / "Dockerfile"

        subprocess.run(
            f"docker build -t {self.image_name} -f {dockerfile_path.absolute()} {docker_proj_path.absolute()}",
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
        import fnmatch

        allowed_patterns = [
            "*.c",
            "*.h",
            "*.cpp",
            "*.cc",
            "*.cxx",
            "*.hpp",
            "*.hxx",
            "*.hh",
        ]
        exclude_dirs = {"aflplusplus", "fuzztest", "honggfuzz", "libfuzzer"}

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

                    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                    shutil.copy2(src_path, dst_path)

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
                + f"FROM aixcc-afc/{self.project_name}-sarif"
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
        env["CFLAGS"] = OSS_FUZZ_DEFAULT_CFLAGS + " -O0 -g -fno-inline"
        env["CXXFLAGS"] = OSS_FUZZ_DEFAULT_CXXFLAGS + " -O0 -g -fno-inline"

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
def build_codeql_db(oss_fuzz_docker: OssFuzzDocker, language: str):
    if language == "jvm":
        language = "java"

    if language == "java":
        build_cmd = '"compile"'
    else:
        build_cmd = '"compile"'

    db_path = "/out/codeql"

    if (OUT_DIR / "codeql").exists():
        try:
            shutil.rmtree(OUT_DIR / "codeql")
        except Exception as e:
            logger.warning("Please remove the codeql db manually")
            raise e

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

    oss_fuzz_docker.exec(cmd)


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


@log_func
def _svf_create_callgraph(oss_fuzz_docker: OssFuzzDocker):
    for harness in HARNESS_NAMES.split(":"):
        harness_path = f"/out/{harness}"

        # Check if the call graph already exists
        call_graph_path = f"/out/SVF/call_graph_{SVF_MODE}_{harness}.dot"

        cmd = " ".join(
            [
                "bash -c",
                f"'wpa -{SVF_MODE} -dump-callgraph {harness_path}.bc && mv callgraph_final.dot {call_graph_path}'",
            ]
        )

        oss_fuzz_docker.exec(cmd)

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
        _svf_create_callgraph(oss_fuzz_docker)
    except Exception as e:
        error(f"Error in build_SVF_dot: {e}")
        error(f"Do not use SVF for {PROJECT_NAME}")
        (BUILD_SHARED_DIR / "AUX_FAILED").touch()


@log_func
def _create_cpg(oss_fuzz_docker: OssFuzzDocker):
    cpg_path = f"/out/joern/cpg.bin"

    match PROJECT_LANGUAGE:
        case "c":
            cmd = " ".join(
                [
                    f"/opt/joern/joern-cli/frontends/c2cpg/target/universal/stage/bin/c2cpg",
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
        case "cpp":
            cmd = " ".join(
                [
                    f"/opt/joern/joern-cli/frontends/c2cpg/target/universal/stage/bin/c2cpg",
                    "/src",
                    "--exclude=/src/aflplusplus",
                    "--exclude=/src/fuzztest",
                    "--exclude=/src/honggfuzz",
                    "--exclude=/src/libfuzzer",
                    "-J-Xmx12g",
                    "--output=" + cpg_path,
                ]
            )
        case "jvm":
            cmd = " ".join(
                [
                    f"/opt/joern/joern-cli/frontends/javasrc2cpg/target/universal/stage/bin/javasrc2cpg",
                    "/src",
                    "--exclude=/src/aflplusplus",
                    "--exclude=/src/fuzztest",
                    "--exclude=/src/honggfuzz",
                    "--exclude=/src/libfuzzer",
                    "-J-Xmx12g",
                    "--output=" + cpg_path,
                ]
            )
        case _:
            raise ValueError(f"Unsupported language: {PROJECT_LANGUAGE}")

    oss_fuzz_docker.exec(cmd)


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
def copy_essential_out_to_shared_build():
    if not _archive_dir_shell(CODEQL_OUT_DIR, OUT_DIR / "codeql.tar.gz"):
        error("Failed to archive CodeQL output.")
    if not _archive_dir_shell(JOERN_OUT_DIR, OUT_DIR / "joern.tar.gz"):
        error("Failed to archive Joern output.")

    shutil.copy(OUT_DIR / "codeql.tar.gz", BUILD_SHARED_DIR / "codeql.tar.gz")
    shutil.copy(OUT_DIR / "joern.tar.gz", BUILD_SHARED_DIR / "joern.tar.gz")

    (BUILD_SHARED_DIR / "ESSENTIAL_DONE").touch()


@log_func
def copy_poc_gen_out_to_shared_build():
    if not _archive_dir_shell(CPG_SRC_DIR, OUT_DIR / "cpg_src.tar.gz"):
        error("Failed to archive CPG SRC output.")
    if not _archive_dir_shell(DEBUG_DIR, OUT_DIR / "debug.tar.gz"):
        error("Failed to archive DEBUG output.")

    shutil.copy(OUT_DIR / "cpg_src.tar.gz", BUILD_SHARED_DIR / "cpg_src.tar.gz")
    shutil.copy(OUT_DIR / "debug.tar.gz", BUILD_SHARED_DIR / "debug.tar.gz")

    (BUILD_SHARED_DIR / "POC_GEN_DONE").touch()


@log_func
def copy_aux_out_to_shared_build():
    if not _archive_dir_shell(SVF_OUT_DIR, OUT_DIR / "SVF.tar.gz"):
        error("Failed to archive SVF output.")

    shutil.copy(OUT_DIR / "SVF.tar.gz", BUILD_SHARED_DIR / "SVF.tar.gz")

    (BUILD_SHARED_DIR / "AUX_DONE").touch()


def clean_up():
    for dir in [SOURCE_DIR, OUT_DIR]:
        shutil.rmtree(dir, ignore_errors=True)


if __name__ == "__main__":
    clean_up()

    log("Starting build...")

    source_dir = setup_challenge_project()
    setup_oss_fuzz_projects()
    setup_docker_volumes()
    with OssFuzzDocker(PROJECT_NAME, PROJECT_LANGUAGE, source_dir) as oss_fuzz_docker:
        build_codeql_db(oss_fuzz_docker, PROJECT_LANGUAGE)
        build_joern_cpg(oss_fuzz_docker)
        copy_essential_out_to_shared_build()

        if PROJECT_LANGUAGE in ["c", "cpp", "c++"]:
            with OssFuzzDebugDocker(
                PROJECT_NAME, PROJECT_LANGUAGE, source_dir
            ) as oss_fuzz_debug_docker:
                copy_cpg_src(oss_fuzz_docker)
                prepare_debug(oss_fuzz_debug_docker)
                copy_poc_gen_out_to_shared_build()

    if PROJECT_LANGUAGE in ["c", "cpp", "c++"]:
        with OssFuzzDocker(
            PROJECT_NAME, PROJECT_LANGUAGE, source_dir
        ) as oss_fuzz_docker:
            env_dict = _get_env_dict(oss_fuzz_docker)
            build_SVF_dot(oss_fuzz_docker, env_dict)

    copy_aux_out_to_shared_build()

    log("All done!")
