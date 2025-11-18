import subprocess
import time
from pathlib import Path

from crete.atoms.path import DEFAULT_CACHE_DIRECTORY, PACKAGES_DIRECTORY
from python_oss_fuzz.language_server_protocol.functions import (
    create_project_lsp,
    prepare_lsp_service,
)
from python_oss_fuzz.path.globals import (
    OSS_FUZZ_BASE_IMAGE_TAG,
    TEAM_ATLANTA_DOCKER_REGISTRY,
    TEAM_ATLANTA_IMAGE_VERSION,
)

MAX_RETRIES = 3


def main(project_name: str | None = None, source_directory: Path | None = None):
    is_success = True
    message = ""
    system_check()

    initialize_cache_directory()

    prepare_oss_fuzz_images(project_name)

    try:
        build_call_tracer_llvm_pass()
    except Exception:
        is_success = False
        message += "Failed to build call tracer llvm\n"

    try:
        build_lsp_docker_image()
        if project_name:
            create_project_lsp(project_name)
        # This is an optimization to prepare LSP service when CRS gets a **challenge project**.
        if source_directory:
            assert project_name is not None
            prepare_lsp_service(project_name, source_directory)
    except Exception:
        is_success = False
        message += "Failed to build lsp docker image\n"

    if not is_success:
        raise Exception(message)


def system_check():
    # wait docker service to be ready
    while not docker_service_ready():
        time.sleep(1)


def docker_service_ready():
    try:
        run("docker ps")
        return True
    except subprocess.CalledProcessError:
        return False


def initialize_cache_directory():
    if not DEFAULT_CACHE_DIRECTORY.exists():
        DEFAULT_CACHE_DIRECTORY.mkdir(parents=True, exist_ok=True)


def prepare_oss_fuzz_images(project_name: str | None):
    _pull_from_aixcc_registry("base-runner")
    _pull_from_aixcc_registry("base-runner-debug")

    # This is an optimization to build `project-lsp` Docker image when CRS gets a
    # **challenge project**. Without this, it will be built when CRS gets a **detection**.

    # Create a new docker for rr-based backtracing.
    # This image is required due to the several reasons as follows:
    # (1) Current rr-backtracer component needs non-standard python packages (e.g., capstone, etc). However, our crete's static gdb cannot import such external libraries.
    # (2) RR conflicts with prepared binaries in /usr/local/bin (i.e., gdb, gdbserver, and python3.10) of base-runner-debug image.
    # (3) RR's watch command on register is (a way) much faster with gdb 16.2 version.

    # _try_pull_or_build_from_atlanta_registry(
    #     "rr-backtracer", RR_BACKTRACER_DIRECTORY, "./Dockerfile"
    # )


def _pull_from_aixcc_registry(image_name: str):
    run(
        f"docker pull ghcr.io/aixcc-finals/{image_name}:{OSS_FUZZ_BASE_IMAGE_TAG}",
        cwd=Path("."),
    )


def _try_pull_or_build_from_atlanta_registry(
    image_name: str, build_path: Path, dockerfile: str
):
    try:
        run(
            f"docker pull {TEAM_ATLANTA_DOCKER_REGISTRY}/{image_name}:{TEAM_ATLANTA_IMAGE_VERSION}",
            cwd=build_path,
        )
    except subprocess.CalledProcessError:  # Test server does not support `docker pull` for TEAM_ATLANTA_DOCKER_REGISTRY yet.
        run(
            f"docker build . -t {TEAM_ATLANTA_DOCKER_REGISTRY}/{image_name}:{TEAM_ATLANTA_IMAGE_VERSION} -f {dockerfile} --build-arg IMG_TAG={OSS_FUZZ_BASE_IMAGE_TAG}",
            cwd=build_path,
        )


def build_call_tracer_llvm_pass():
    for _ in range(MAX_RETRIES):
        try:
            run(f"rm -rf {PACKAGES_DIRECTORY}/cpp_function_call_logging/build")
            run(
                f"python {PACKAGES_DIRECTORY}/cpp_function_call_logging/build_llvm_pass.py"
            )
            break
        except subprocess.CalledProcessError:
            pass


def build_lsp_docker_image():
    _try_pull_or_build_from_atlanta_registry(
        "crete-lsp", Path(f"{PACKAGES_DIRECTORY}/python_lsp"), "./Dockerfile"
    )


def run(cmd: str, cwd: Path = Path.cwd()):
    print(f"Running: {cmd}" + (f" in {cwd}" if cwd else ""))
    subprocess.run(cmd, shell=True, check=True, cwd=cwd)


if __name__ == "__main__":
    source_directory = Path("/home/ubuntu/cp_sources/")
    main()
