import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from crete.commons.interaction.functions import run_command
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.path.globals import OSS_FUZZ_BASE_IMAGE_TAG, OSS_FUZZ_DIRECTORY


def _prepare_docker_cmdline(
    image: str,
    cmd: List[str],
    tty: bool = False,
    files_to_mount: List[Tuple[Path, str]] = [],
    extra_docker_args: List[str] = [],
    env: dict[str, str] = {},
) -> List[str]:
    """
    Prepare docker command and kwargs for execution.

    Args:
        image: Docker image name
        cmd: Command to execute inside the container
        tty: Allocate a pseudo-TTY (-t)
        files_to_mount: Files to mount in the container

    Returns:
        List of strings for docker command
    """
    docker_cmd = [
        "docker",
        "run",
        "--privileged",
        "--shm-size=2g",
        "--rm",
        "-i",
    ]

    if tty:
        docker_cmd.append("-t")

    for src, dst in files_to_mount:
        docker_cmd.extend(["-v", f"{src.resolve()}:{dst}"])

    if env:
        for key, value in env.items():
            docker_cmd.append("-e")
            docker_cmd.append(f"{key}={value}")

    if extra_docker_args:
        docker_cmd.extend(extra_docker_args)

    docker_cmd.extend([image, *cmd])

    return docker_cmd


def docker_shell(
    image: str,
    out_directory: Path,
    work_directory: Path,
    cwd: Optional[Path] = None,
    stdin: Optional[int] = None,
) -> subprocess.Popen[bytes]:
    """
    Execute a command in a Docker container using Popen.

    Args:
        image: Docker image name
        out_directory: Directory to mount as /out in container
        work_directory: Directory to mount as /work in container
        cwd: Working directory for the subprocess
        stdin: Standard input file descriptor

    Returns:
        Popen object
    """
    docker_cmd = _prepare_docker_cmdline(
        image,
        ["/bin/bash"],
        files_to_mount=create_docker_mount_args(out_directory, work_directory),
        tty=True,
    )

    # Return Popen object for interactive use
    return subprocess.Popen(
        docker_cmd,
        cwd=cwd,
        close_fds=True,
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def docker_execute(
    image: str,
    cmd: List[str],
    files_to_mount: List[Tuple[Path, str]] = [],
    env: Dict[str, str] = {},
    timeout: Optional[int] = None,
    extra_docker_args: List[str] = [],
) -> tuple[str, str]:
    """
    Execute a command in a Docker container using run.

    Args:
        image: Docker image name
        cmd: Command to execute inside the container
        timeout: Timeout for the command
        files_to_mount: Files to mount in the container

    Returns:
        Tuple of (stdout, stderr)
    """
    docker_cmd = _prepare_docker_cmdline(
        image,
        cmd,
        files_to_mount=files_to_mount,
        extra_docker_args=extra_docker_args,
        env=env,
    )
    cwd = OSS_FUZZ_DIRECTORY

    return run_command((docker_cmd, cwd), timeout=timeout)


def create_docker_mount_args(
    out_directory: Path, work_directory: Path
) -> List[Tuple[Path, str]]:
    return [
        (out_directory, "/out"),
        (work_directory, "/work"),
    ]


def build_fuzzers_extended(
    project_name: str,
    source_directory: Path,
    sanitizer: str = "address",
    default_command: str = "compile",
    extra_docker_args: List[str] = [],
) -> tuple[str, str]:
    env = {
        "FUZZING_ENGINE": "libfuzzer",
        "SANITIZER": sanitizer,
        "ARCHITECTURE": "x86_64",
        "FUZZING_LANGUAGE": AIxCCChallengeProjectYaml.from_project_name(
            project_name
        ).language,
    }
    return docker_execute(
        f"aixcc-afc/{project_name}",
        [
            "/bin/bash",
            "-c",
            f"WORK_DIR=$PWD && pushd $SRC && rm -rf $WORK_DIR && cp -rf /local-source-mount $WORK_DIR && popd && {default_command}",
        ],
        files_to_mount=create_docker_mount_args(
            OSS_FUZZ_DIRECTORY / "build/out" / project_name,
            OSS_FUZZ_DIRECTORY / "build/work" / project_name,
        ),
        env=env,
        extra_docker_args=[
            "-v",
            f"{source_directory}:/local-source-mount:ro",
            *extra_docker_args,
        ],
    )


def reproduce_extended(
    project_name: str,
    harness_name: str,
    blob: bytes,
    fuzzer_args: List[str] = [],
    cmd: List[str] | None = None,
    extra_docker_args: List[str] = [],
) -> tuple[str, str]:
    with tempfile.NamedTemporaryFile() as f:
        f.write(blob)
        f.flush()
        return docker_execute(
            f"ghcr.io/aixcc-finals/base-runner:{OSS_FUZZ_BASE_IMAGE_TAG}",
            cmd=cmd or ["reproduce", harness_name, "-runs=100", *fuzzer_args],
            files_to_mount=create_docker_mount_args(
                OSS_FUZZ_DIRECTORY / "build/out" / project_name,
                OSS_FUZZ_DIRECTORY / "build/work" / project_name,
            ),
            extra_docker_args=[
                "-v",
                f"{f.name}:/testcase",
                *extra_docker_args,
            ],
        )
