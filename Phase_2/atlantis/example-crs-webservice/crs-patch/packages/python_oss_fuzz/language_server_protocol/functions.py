import atexit
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import pylspclient
from crete.commons.docker.functions import build_fuzzers_extended
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.logging.hooks import use_logger
from crete.framework.environment.functions import rsync_directory
from python_aixcc_challenge.language.types import Language
from python_docker.image.functions import (
    destroy_container,
    get_exposed_port,
    get_running_containers,
    is_exited,
    is_running,
)

from python_oss_fuzz.path.functions import get_oss_fuzz_project_path
from python_oss_fuzz.path.globals import (
    OSS_FUZZ_DIRECTORY,
    OSS_FUZZ_HELPER_FILE,
    TEAM_ATLANTA_DOCKER_REGISTRY,
    TEAM_ATLANTA_IMAGE_VERSION,
)

_logger = use_logger()


@dataclass
class StatusMessage:
    type: str
    message: str


def start_language_server(project_name: str, source_directory: Path) -> bool:
    container_name = make_lsp_container_name(project_name)
    if is_running(container_name):
        return True
    elif is_exited(container_name):
        destroy_container(container_name)

    # **`project_lsp`** is a variant of the given project that is used to run the language
    # server. It's a copy of the given project with some modifications to the Dockerfile
    # to run the language server.
    # `oss-fuzz/projects/foo` -> `oss-fuzz/projects/foo-lsp`
    if not create_project_lsp(project_name):
        return False

    prepare_lsp_service(project_name, source_directory)
    if not _run_lsp_service(project_name, source_directory, container_name):
        return False

    atexit.register(stop_language_server, project_name)
    return True


def stop_language_server(project_name: str):
    container_name = make_lsp_container_name(project_name)
    if is_running(container_name):
        destroy_container(container_name)


def prepare_lsp_service(project_name: str, source_directory: Path):
    project_lsp_name = _make_project_lsp_name(project_name)
    try:
        build_fuzzers_extended(
            project_lsp_name, source_directory, default_command="/prepare.sh"
        )
    except CommandInteractionError as e:
        _logger.error(f"Failed to run LSP prepare docker: {e.stderr}")
        raise


def _run_lsp_service(
    project_name: str, source_directory: Path, container_name: str
) -> bool:
    """Run the LSP container to handle LSP requests during the Crete execution."""
    project_lsp_name = _make_project_lsp_name(project_name)
    try:
        build_fuzzers_extended(
            project_lsp_name,
            source_directory,
            default_command="/run.sh",
            extra_docker_args=["-p", "0:7000", "--name", container_name, "-d"],
        )
    except CommandInteractionError as e:
        _logger.error(f"Failed to run LSP service: {e.stderr}")
        raise
    ret = _wait_until_lsp_service_started(container_name)
    subprocess.run(["docker", "logs", container_name])
    return ret


def _wait_until_lsp_service_started(container_name: str) -> bool:
    max_wait_time = 10
    start_time = time.time()

    def check_socat_running() -> bool:
        p = subprocess.run(
            ["docker", "exec", "-i", container_name, "ps", "aux"],
            capture_output=True,
            text=True,
        )
        return "socat" in p.stdout

    while time.time() - start_time <= max_wait_time:
        if check_socat_running():
            return True
        time.sleep(1)

    _logger.error("LSP service did not start in time")
    return False


def get_all_language_servers() -> list[str]:
    return [
        container
        for container in get_running_containers()
        if is_lsp_container(container)
    ]


def _append_status_message(
    status_messages: list[StatusMessage],
) -> Callable[[dict[str, Any]], None]:
    def _append_status_message_inner(params: dict[str, Any]) -> None:
        _logger.debug(f"Language server status: {params['type']} {params['message']}")
        status_messages.append(StatusMessage(params["type"], params["message"]))

    return _append_status_message_inner


def _wait_until_language_server_is_ready(
    status_messages: list[StatusMessage], language: Language, timeout: int = 120
):
    if language != "jvm":
        return

    _logger.info("Waiting for JAVA language server to become ready...")
    start_time = time.time()

    while True:
        if time.time() - start_time > timeout:
            break
        time.sleep(1)
        if any(
            status_message.type == "Started" and status_message.message == "Ready"
            for status_message in status_messages
        ):
            _logger.info("Language server is ready!")
            break


def start_language_server_session(
    project_name: str, language: Language
) -> Optional[pylspclient.LspClient]:
    status_messages: list[StatusMessage] = []
    client = _connect_to_language_server(project_name, status_messages)
    if not _initialize(client, project_name):
        return None
    _wait_until_language_server_is_ready(status_messages, language)
    return client


def _connect_to_language_server(
    project_name: str, status_messages: list[StatusMessage]
) -> pylspclient.LspClient:
    assert make_lsp_container_name(project_name) in get_running_containers()
    port = _find_used_port(project_name)
    sock = socket.create_connection(("localhost", port))
    endpoint = pylspclient.LspEndpoint(
        pylspclient.JsonRpcEndpoint(sock.makefile("wb"), sock.makefile("rb")),
        notify_callbacks={"language/status": _append_status_message(status_messages)},
        timeout=10,
    )
    endpoint.daemon = True
    return pylspclient.LspClient(endpoint)


def _initialize(client: pylspclient.LspClient, project_name: str) -> bool:
    source_directory_in_docker = workdir_of_project(project_name)
    _logger.info(f"Initializing language server for {project_name}...")
    try:
        client.initialize(  # type: ignore
            processId=None,
            rootPath=None,
            rootUri=f"file://{source_directory_in_docker}",
            initializationOptions=None,
            capabilities={},
            trace="off",
            workspaceFolders=None,
        )
    except TimeoutError:
        _logger.error("Language server initialization timed out")
        return False
    _logger.info("Language server initialized!")
    return True


def make_lsp_container_name(project_name: str) -> str:
    pid = os.getpid()
    name = f"crete-lsp-{pid}-{project_name}"
    return name.replace("/", "-").replace(":", "-")


def is_lsp_container(container_name: str) -> bool:
    pid = os.getpid()
    return container_name.startswith(f"crete-lsp-{pid}-")


# Copied from infra/helper.py
WORKDIR_REGEX = re.compile(r"\s*WORKDIR\s*([^\s]+)")


# Copied from infra/helper.py
def workdir_from_lines(lines: list[str], default: str = "/src"):
    """Gets the WORKDIR from the given lines."""
    for line in reversed(lines):  # reversed to get last WORKDIR.
        match = re.match(WORKDIR_REGEX, line)
        if match:
            workdir = match.group(1)
            workdir = workdir.replace("$SRC", "/src")

            if not os.path.isabs(workdir):
                workdir = os.path.join("/src", workdir)

            return os.path.normpath(workdir)

    return default


def workdir_of_project(project_name: str) -> str:
    dockerfile_path = get_oss_fuzz_project_path(project_name) / "Dockerfile"
    lines = dockerfile_path.read_text().splitlines()
    return workdir_from_lines(lines)


def _find_used_port(project_name: str) -> int:
    container_name = make_lsp_container_name(project_name)
    # TODO: Avoid hardcoding the port number
    return get_exposed_port(container_name, 7000)


def create_project_lsp(project_name: str) -> bool:
    assert _build_project_image(project_name)
    _copy_project_directory_for_lsp(project_name)
    _modify_dockerfile_for_lsp(project_name)
    return _build_project_image(_make_project_lsp_name(project_name))


def _build_project_image(project_name: str) -> bool:
    build_cmd = [
        "python3",
        str(OSS_FUZZ_HELPER_FILE),
        "build_image",
        "--cache",
        "--no-pull",
        project_name,
    ]

    try:
        subprocess.check_call(
            build_cmd,
            cwd=OSS_FUZZ_DIRECTORY,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _copy_project_directory_for_lsp(project_name: str):
    project_lsp_name = _make_project_lsp_name(project_name)
    project_lsp_path = get_oss_fuzz_project_path(project_lsp_name)
    original_project_path = get_oss_fuzz_project_path(project_name)
    rsync_directory(original_project_path, project_lsp_path)


def _modify_dockerfile_for_lsp(project_name: str):
    template_path = Path(__file__).parent / "docker" / "Dockerfile.template"
    lsp_image = f"{TEAM_ATLANTA_DOCKER_REGISTRY}/crete-lsp:{TEAM_ATLANTA_IMAGE_VERSION}"

    dockerfile_content = template_path.read_text().format(
        PROJECT_NAME=project_name,
        LSP_IMAGE_NAME=lsp_image,
    )

    project_lsp_name = _make_project_lsp_name(project_name)
    lsp_dockerfile_path = get_oss_fuzz_project_path(project_lsp_name) / "Dockerfile"
    lsp_dockerfile_path.write_text(dockerfile_content)


def _make_project_lsp_name(project_name: str) -> str:
    return f"{project_name}-lsp"
