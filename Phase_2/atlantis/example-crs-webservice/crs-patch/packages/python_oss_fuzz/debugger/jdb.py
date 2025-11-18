import re
import uuid
from contextlib import contextmanager

import pexpect
from crete.commons.docker.functions import reproduce_extended
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.logging.hooks import use_logger
from python_docker.image.functions import destroy_container, is_running
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY

_logger = use_logger(__name__)


@contextmanager
def start_jdb_session(project_name: str, harness_name: str, blob: bytes):
    _assert_harness_exists(project_name, harness_name)
    container_name = _make_container_name(project_name, harness_name)
    try:
        reproduce_extended(
            project_name,
            harness_name,
            blob,
            [
                "--",
                '--additional_jvm_args="-agentlib\\:jdwp=transport=dt_socket,server=y,suspend=y,address=1234"',
            ],
            extra_docker_args=[
                "-d",
                "--name",
                container_name,
            ],
        )
    except CommandInteractionError as e:
        _logger.error(f"Failed to run jdb session: {e.stderr}")
        raise
    if not is_running(container_name):
        _logger.error("JDB session failed: Container %s is not running", container_name)
        raise RuntimeError("JDB session failed: Container is not running")

    child: "pexpect.spawn[str]" = pexpect.spawn(
        f"docker exec -it {container_name} jdb -attach 1234",
        encoding="utf-8",
        timeout=60,
    )

    try:
        child.expect("main\\[1\\] ", timeout=10)
    except pexpect.EOF:
        _logger.error("Failed to attach to jdb session")
        raise

    try:
        yield child
    finally:
        if is_running(container_name):
            run_jdb_command(child, "quit")
            destroy_container(container_name)


def run_jdb_command(p: "pexpect.spawn[str]", jdb_command: str) -> str | None:
    _logger.info("jdb> %s", jdb_command)
    p.sendline(jdb_command)
    try:
        p.expect("main\\[1\\] ", timeout=30)  # 25 (libfuzzer timeout) + 5 (extra time)
    except pexpect.EOF:
        pass
    out = p.before
    if out is None:
        _logger.error("No output from jdb command: %s", jdb_command)
    else:
        _logger.info(out)
    return out


def run_jdb_commands(
    project_name: str,
    harness_name: str,
    blob: bytes,
    jdb_commands: list[str],
) -> list[str | None]:
    results: list[str | None] = []
    with start_jdb_session(project_name, harness_name, blob) as p:
        for command in jdb_commands:
            results.append(run_jdb_command(p, command))
    return results


def _make_container_name(project_name: str, harness_name: str) -> str:
    name = f"{project_name}_{harness_name}_{uuid.uuid4()}"
    return re.sub(r"[^a-z0-9_-]", "_", name)


def _assert_harness_exists(project_name: str, harness_name: str):
    harness_path = OSS_FUZZ_DIRECTORY / "build/out" / project_name / harness_name
    assert harness_path.exists(), (
        f"Harness {harness_name} does not exist in project {project_name}"
    )
