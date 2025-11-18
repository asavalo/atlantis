import os
from pathlib import Path

from python_oss_fuzz.path.globals import OSS_FUZZ_BASE_IMAGE_TAG

from crete.commons.docker.functions import docker_execute
from crete.commons.logging.context_managers import logging_performance
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.functions import rsync_directory
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


def _run_docker_command(
    command: str,
    files_to_mount: list[tuple[Path, str]] = [],
) -> tuple[str, str]:
    return docker_execute(
        image=f"ghcr.io/aixcc-finals/base-runner:{OSS_FUZZ_BASE_IMAGE_TAG}",
        cmd=["/bin/bash", "-c", command],
        files_to_mount=files_to_mount,
    )


def _set_owner(pool: EnvironmentPoolProtocol, context: EnvironmentContext):
    # Currently, the docker container is running as root, so we need to set
    # the owner of the directories to the current user
    with logging_performance(context, "Setting owner"):
        _run_docker_command(
            f"chown -R {os.getuid()}:{os.getgid()} /to-chown",
            [
                (pool.out_directory, "/to-chown/out"),
                (pool.work_directory, "/to-chown/work"),
                (pool.source_directory, "/to-chown/src"),
            ],
        )


def load_environment(
    pool: EnvironmentPoolProtocol,
    context: EnvironmentContext,
    snapshot_directory: Path,
):
    _set_owner(pool, context)

    sanitizer_name = context.get("sanitizer_name", "address")
    rsync_directory(
        snapshot_directory / sanitizer_name / "out",
        pool.out_directory,
    )

    rsync_directory(
        snapshot_directory / sanitizer_name / "src",
        pool.source_directory,
    )

    rsync_directory(
        snapshot_directory / sanitizer_name / "work",
        pool.work_directory,
    )


def save_environment(
    pool: EnvironmentPoolProtocol,
    context: EnvironmentContext,
    snapshot_directory: Path,
):
    _set_owner(pool, context)

    sanitizer_name = context.get("sanitizer_name", "address")

    # Store the output directory
    rsync_directory(pool.out_directory, snapshot_directory / sanitizer_name / "out")

    # Store the source directory
    rsync_directory(pool.source_directory, snapshot_directory / sanitizer_name / "src")

    # Work directory
    rsync_directory(pool.work_directory, snapshot_directory / sanitizer_name / "work")
