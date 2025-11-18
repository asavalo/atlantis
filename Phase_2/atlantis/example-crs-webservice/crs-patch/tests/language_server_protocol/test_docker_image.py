import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path
from unittest.mock import patch

from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.language.types import Language
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.language_server_protocol.functions import (
    create_project_lsp,
    make_lsp_container_name,
    prepare_lsp_service,
)
from python_oss_fuzz.path.functions import get_oss_fuzz_project_path
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY, OSS_FUZZ_HELPER_FILE


def _check_command_in_cp_docker(project_name: str, command: list[str]):
    docker_image_name = f"aixcc-afc/{project_name}"
    subprocess.check_output(
        ["docker", "run", "--rm", docker_image_name, *command],
    )


def _check_prepare_lsp_service(project_lsp_name: str, language: Language):
    if language in ["c", "cpp", "c++"]:
        work_dir = OSS_FUZZ_DIRECTORY / "build/work" / project_lsp_name
        assert (work_dir / "compile_commands.json").exists()
        compile_commands = json.load(open(work_dir / "compile_commands.json"))
        assert len(compile_commands) > 0
    elif language == "jvm":
        pass


def _verify_docker_image_exists(project_lsp_name: str):
    subprocess.check_output(
        ["docker", "images", f"aixcc-afc/{project_lsp_name}"],
    )


def _cleanup_lsp_resources(project_lsp_name: str, container_name: str):
    """Clean up Docker image and project directories created during LSP testing."""
    subprocess.run(
        ["docker", "rmi", f"aixcc-afc/{project_lsp_name}"],
    )
    subprocess.run(
        ["docker", "rm", "-f", container_name],
    )
    if get_oss_fuzz_project_path(project_lsp_name).exists():
        chown_cmd = f"chown -R {os.getuid()}:{os.getgid()}"
        subprocess.run(
            [
                "python3",
                OSS_FUZZ_HELPER_FILE,
                "execute",
                project_lsp_name,
                "--exec",
                f"{chown_cmd} /src && {chown_cmd} /work && {chown_cmd} /out",
            ],
            cwd=OSS_FUZZ_DIRECTORY,
        )
        shutil.rmtree(OSS_FUZZ_DIRECTORY / "build/work" / project_lsp_name)
        shutil.rmtree(OSS_FUZZ_DIRECTORY / "build/out" / project_lsp_name)
        shutil.rmtree(get_oss_fuzz_project_path(project_lsp_name))


def test_lsp_docker_image(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    source_directory, detection_toml_file = detection_c_mock_c_cpv_0
    project_name = AIxCCChallengeProjectDetection.from_toml(
        detection_toml_file
    ).project_name
    language = AIxCCChallengeProjectYaml.from_project_name(project_name).language

    project_lsp_name = f"{project_name}-lsp-test-{str(uuid.uuid4())}"
    container_name = make_lsp_container_name(project_name)

    try:
        with patch(
            "python_oss_fuzz.language_server_protocol.functions._make_project_lsp_name",
            return_value=project_lsp_name,
        ):
            # Create LSP project and verify docker image was created
            assert create_project_lsp(project_name)
            _verify_docker_image_exists(project_lsp_name)

            # Check for required tools in the Docker container
            _check_command_in_cp_docker(project_lsp_name, ["socat", "-h"])
            _check_command_in_cp_docker(project_lsp_name, ["bear", "-h"])
            _check_command_in_cp_docker(project_lsp_name, ["clangd-18", "-h"])
            _check_command_in_cp_docker(
                project_lsp_name, ["/opt/eclipse-jdt-ls/bin/jdtls", "-h"]
            )

            # Verify LSP preparation
            prepare_lsp_service(project_name, source_directory)
            _check_prepare_lsp_service(project_lsp_name, language)
    finally:
        _cleanup_lsp_resources(project_lsp_name, container_name)
