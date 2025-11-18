import hashlib
import json
import logging
import os
import sys
import tempfile
import base64
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, List, NoReturn, Optional

import click
import click.core
import yaml
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY as CACHE_DIRECTORY
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from pydantic import BaseModel
from python_aixcc_challenge.detection.models import (
    AIxCCChallengeDeltaMode,
    AIxCCChallengeProjectDetection,
)
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY


class ReturnCode(IntEnum):
    """Exit codes for the detection checker script."""

    SUCCESS = 0
    BUILD_IMAGE_ERROR = 1
    BUILD_FUZZERS_ERROR = 2
    REPRODUCE_ERROR = 3
    CHECK_BUILD_ERROR = 4
    GIT_CLONE_ERROR = 10
    GIT_RESET_ERROR = 11
    GIT_CLEAN_ERROR = 12
    GIT_COMMIT_NOT_FOUND = 13
    GIT_FETCH_ERROR = 14


def exit_with_code(code: ReturnCode, message: Optional[str] = None) -> NoReturn:
    """Exit the program with the given exit code and optional message."""
    if message:
        logging.info(message)
    sys.exit(code)


class ProjectInfo(BaseModel):
    git_url: str
    project_name: str
    source_directory: Path
    project_yaml: AIxCCChallengeProjectYaml
    detection_yaml: AIxCCChallengeProjectDetection


class OrderedGroup(click.Group):
    def __init__(
        self,
        name: Optional[str] = None,
        commands: Optional[Dict[str, click.core.Command]] = None,
        **attrs: Any,
    ) -> None:
        super(OrderedGroup, self).__init__(name, commands, **attrs)

    def list_commands(self, ctx: click.Context) -> List[str]:
        return ["full", "build", "reproduce"]


@click.group(cls=OrderedGroup)
def cli():
    """preprocess: Preprocess the repository"""
    pass


@cli.command(name="full")
@click.argument(
    "detection_paths", nargs=-1, type=click.Path(exists=True, path_type=Path)
)
@click.option("-o", "--log-file", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def cmd_full(
    detection_paths: tuple[Path, ...], log_file: Optional[Path], verbose: bool
):
    """Execute build_image, build_fuzzers, and reproduce in sequence for multiple detection paths"""
    setup_logging(log_file, debug=verbose)

    for detection_path in detection_paths:
        project_info = get_project_info(detection_path)
        logging.debug(f"Processing project: {project_info.project_name}")
        logging.debug(f"Repository: {project_info.git_url}")
        logging.debug(f"Source directory: {project_info.source_directory}")

        if (build_result := validate_build(project_info)) != ReturnCode.SUCCESS:
            logging.error(f"{detection_path}: {build_result.name.lower()}")
            continue

        if (reproduce_result := validate_reproduce(project_info)) != ReturnCode.SUCCESS:
            logging.error(f"{detection_path}: {reproduce_result.name.lower()}")
            continue

        logging.info(f"{detection_path}: success")


@cli.command(name="build")
@click.argument(
    "detection_paths", nargs=-1, type=click.Path(exists=True, path_type=Path)
)
@click.option("-o", "--log-file", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def cmd_build(
    detection_paths: tuple[Path, ...], log_file: Optional[Path], verbose: bool
):
    """Execute build_image and build_fuzzers for multiple detection paths"""
    setup_logging(log_file, debug=verbose)

    for detection_path in detection_paths:
        project_info = get_project_info(detection_path)
        logging.debug(f"Processing project: {project_info.project_name}")
        logging.debug(f"Repository: {project_info.git_url}")
        logging.debug(f"Source directory: {project_info.source_directory}")

        if (build_result := validate_build(project_info)) != ReturnCode.SUCCESS:
            logging.error(f"{detection_path}: {build_result.name.lower()}")
            continue

        logging.info(f"{detection_path}: success")


@cli.command(name="reproduce")
@click.argument(
    "detection_paths", nargs=-1, type=click.Path(exists=True, path_type=Path)
)
@click.option("-o", "--log-file", type=click.Path(path_type=Path), default=None)
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option(
    "-k", "--keep-blob", is_flag=True, help="Keep the test case file after reproduction"
)
def cmd_reproduce(
    detection_paths: tuple[Path, ...],
    log_file: Optional[Path],
    verbose: bool,
    keep_blob: bool,
):
    """Test blob_data for multiple detection paths"""
    setup_logging(log_file, debug=verbose)

    for detection_path in detection_paths:
        project_info = get_project_info(detection_path)
        logging.debug(f"Processing project: {project_info.project_name}")
        logging.debug(f"Repository: {project_info.git_url}")
        logging.debug(f"Source directory: {project_info.source_directory}")

        if (
            reproduce_result := validate_reproduce(project_info, keep_blob=keep_blob)
        ) != ReturnCode.SUCCESS:
            logging.error(f"{detection_path}: {reproduce_result.name.lower()}")

        logging.info(f"{detection_path}: success")


# Global cache dictionary
_build_cache: Dict[str, ReturnCode] = {}


def get_project_hash(project_info: ProjectInfo) -> str:
    cache_data = {
        "project_name": project_info.project_name,
        "source_directory": str(project_info.source_directory),
        "git_url": project_info.git_url,
        "checkout_ref": project_info.detection_yaml.mode.checkout_ref(),
    }

    json_str = json.dumps(cache_data, sort_keys=True)
    return hashlib.sha256(json_str.encode()).hexdigest()


def validate_build(project_info: ProjectInfo):
    # Generate cache key from project info
    cache_key = get_project_hash(project_info)

    # Check if cache exists
    if cache_key in _build_cache:
        logging.debug(f"Build cache hit for {project_info.project_name}")
        return _build_cache[cache_key]

    # If no cache, proceed with build
    if (prepare_result := prepare_project(project_info)) != ReturnCode.SUCCESS:
        result = prepare_result
    elif not build_image(project_info):
        result = ReturnCode.BUILD_IMAGE_ERROR
    elif not build_fuzzers(project_info):
        result = ReturnCode.BUILD_FUZZERS_ERROR
    elif not check_build(project_info):
        result = ReturnCode.CHECK_BUILD_ERROR
    else:
        result = ReturnCode.SUCCESS

    _build_cache[cache_key] = result

    return result


def validate_reproduce(project_info: ProjectInfo, keep_blob: bool = False):
    if not reproduce(project_info.detection_yaml, keep_blob=keep_blob):
        return ReturnCode.REPRODUCE_ERROR

    return ReturnCode.SUCCESS


def setup_logging(log_file: Optional[Path] = None, debug: bool = False):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO if not debug else logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    stream_handler = logging.StreamHandler()
    logger.addHandler(stream_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def run_helper(command: str):
    helper_py = OSS_FUZZ_DIRECTORY / "infra" / "helper.py"
    cmd = f"{helper_py} {command}"

    logging.debug(f"Running: {cmd}")
    return run_command((cmd, Path(".")), no_color=True)


def check_git_commit(source_directory: Path, ref: str) -> bool:
    try:
        run_command(
            (
                f"git -C {source_directory} rev-parse --verify {ref}^{{commit}}",
                Path("."),
            ),
            no_color=True,
        )
    except Exception:
        return False
    return True


def get_project_info(detection_path: Path):
    detection_yaml = AIxCCChallengeProjectDetection.from_toml(detection_path)
    project_yaml = (
        OSS_FUZZ_DIRECTORY / "projects" / detection_yaml.project_name / "project.yaml"
    )
    with open(project_yaml, "r") as f:
        project_yaml = yaml.safe_load(f)

    git_url = project_yaml["main_repo"]
    source_directory = CACHE_DIRECTORY / git_url.split("/")[-1].split(".")[0]

    return ProjectInfo(
        project_name=detection_yaml.project_name,
        source_directory=source_directory,
        git_url=git_url,
        project_yaml=project_yaml,
        detection_yaml=detection_yaml,
    )


def prepare_project(project_info: ProjectInfo):
    # Git clone
    if not os.path.exists(project_info.source_directory):
        if (
            os.system(
                f"git clone {project_info.git_url} {project_info.source_directory}"
            )
            != 0
        ):
            return ReturnCode.GIT_CLONE_ERROR
    else:
        if os.system(f"git -C {project_info.source_directory} fetch") != 0:
            return ReturnCode.GIT_FETCH_ERROR

    base_ref = project_info.detection_yaml.mode.base_ref
    if isinstance(project_info.detection_yaml.mode, AIxCCChallengeDeltaMode):
        delta_ref = project_info.detection_yaml.mode.delta_ref
    else:
        delta_ref = None

    if not check_git_commit(project_info.source_directory, base_ref):
        return ReturnCode.GIT_COMMIT_NOT_FOUND

    if delta_ref:
        if not check_git_commit(project_info.source_directory, delta_ref):
            return ReturnCode.GIT_COMMIT_NOT_FOUND

    # Git reset
    if (
        os.system(
            f"git -C {project_info.source_directory} reset --hard {project_info.detection_yaml.mode.checkout_ref()}"
        )
        != 0
    ):
        return ReturnCode.GIT_RESET_ERROR

    # Git clean
    if os.system(f"git -C {project_info.source_directory} clean -fd") != 0:
        return ReturnCode.GIT_CLEAN_ERROR

    return ReturnCode.SUCCESS


def build_image(project_info: ProjectInfo):
    try:
        run_helper(f"build_image {project_info.project_name} --no-pull --cache")
    except Exception:
        return False
    return True


def build_fuzzers(project_info: ProjectInfo):
    if project_info.project_yaml.language == "jvm":
        options = "-e MAVEN_OPTS=-Dmaven.repo.local=/work/mavencache"
    else:
        options = ""

    try:
        run_helper(
            f"build_fuzzers {options} {project_info.project_name} {project_info.source_directory}"
        )
    except Exception:
        return False
    return True


def reproduce(
    detection_yaml: AIxCCChallengeProjectDetection,
    keep_blob: bool = False,
) -> bool:
    assert len(detection_yaml.blobs) > 0, "Blob data is None"
    for blob in detection_yaml.blobs:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(base64.b64decode(blob.blob))
            blob_file = f.name

        try:
            run_helper(
                f"reproduce {detection_yaml.project_name} {blob.harness_name} {blob_file}"
            )
        except CommandInteractionError as e:
            if e.return_code == 1:
                continue
        except Exception:
            pass
        finally:
            try:
                if not keep_blob:
                    os.unlink(blob_file)
                else:
                    logging.info(f"blob_file: {blob_file}")
            except Exception:
                pass

        return False

    return True


def check_build(project_info: ProjectInfo):
    try:
        run_helper(f"check_build {project_info.project_name}")
    except Exception:
        return False
    return True


if __name__ == "__main__":
    cli()
