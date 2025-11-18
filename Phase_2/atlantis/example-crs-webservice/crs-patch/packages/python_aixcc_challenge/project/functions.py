from pathlib import Path

from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.commons.logging.hooks import use_logger
from joblib import Parallel, delayed  # pyright: ignore[reportUnknownVariableType]
from python_docker.image.functions import docker_image_exists
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY, OSS_FUZZ_HELPER_FILE

from ..detection.models import AIxCCChallengeProjectDetection
from ..project.models import (
    AIxCCChallengeProject,
)

_logger = use_logger()


def prepare_aixcc_challenge_projects_from_detection_files(
    detection_files: list[Path],
    cache_directory: Path,
    disable_force_prepare: bool = False,
):
    detections = [
        AIxCCChallengeProjectDetection.from_toml(detection_file)
        for detection_file in detection_files
    ]

    return prepare_aixcc_challenge_projects_from_project_names(
        [detection.project_name for detection in detections],
        cache_directory,
        disable_force_prepare,
    )


def prepare_aixcc_challenge_projects_from_project_names(
    project_names: list[str],
    cache_directory: Path,
    disable_force_prepare: bool = False,
):
    project_infos = [
        AIxCCChallengeProject.from_project_name(project_name)
        for project_name in project_names
    ]

    directories = [
        _aixcc_challenge_project_info_as_directory(project_info, cache_directory)
        for project_info in project_infos
    ]

    projects_to_prepare: list[AIxCCChallengeProject] = []
    for project_info, directory in zip(project_infos, directories):
        if not disable_force_prepare or not directory.exists():
            projects_to_prepare.append(project_info)

    if projects_to_prepare:
        _prepare_aixcc_challenge_projects_from_project_infos(
            projects_to_prepare, cache_directory
        )

    return directories


def _prepare_aixcc_challenge_projects_from_project_infos(
    project_infos: list[AIxCCChallengeProject],
    cache_directory: Path,
):
    _clone_aixcc_challenge_project_repositories(project_infos, cache_directory)

    _build_aixcc_challenge_projects(project_infos, cache_directory)


def _build_aixcc_challenge_projects(
    project_infos: list[AIxCCChallengeProject],
    cache_directory: Path,
):
    Parallel(n_jobs=1)(
        delayed(_build_aixcc_challenge_project)(project_info, cache_directory)
        for project_info in project_infos
    )


def _build_aixcc_challenge_project(
    project_info: AIxCCChallengeProject,
    cache_directory: Path,
):
    try:
        run_command(
            (
                f"docker inspect {docker_image_name(project_info.project_name)}",
                Path.cwd(),
            )
        )
        return
    except Exception:
        pass

    _logger.info(f"Building an oss-fuzz image for {project_info.project_name}")
    run_command(
        (
            f"{OSS_FUZZ_HELPER_FILE} build_image --no-pull {project_info.project_name}",
            OSS_FUZZ_DIRECTORY,
        )
    )


def _clone_aixcc_challenge_project_repositories(
    project_infos: list[AIxCCChallengeProject],
    cache_directory: Path,
):
    Parallel(n_jobs=1)(
        delayed(_clone_repository)(
            project_info,
            cache_directory,
        )
        for project_info in project_infos
    )


def _clone_repository(
    project_info: AIxCCChallengeProject,
    cache_directory: Path,
):
    repository_directory = _aixcc_challenge_project_info_as_directory(
        project_info, cache_directory
    )

    if repository_directory.exists():
        if _commits_all_exists_locally(
            repository_directory, _get_used_commits(project_info)
        ):
            return
        # We need to fetch commits used in the detection (base_ref, delta_ref) locally.
        # `git reset base_ref` will not work if the commit is not fetched.
        run_command(("git fetch --recurse-submodules", repository_directory))
    else:
        _logger.info(f"Cloning {project_info.project_yaml.main_repo}")
        run_command(
            (
                f"git clone --recurse-submodules {project_info.project_yaml.main_repo}",
                cache_directory,
            )
        )
        assert repository_directory.exists(), (
            f"Repository {project_info.project_yaml.main_repo} not found"
        )

    run_command(
        (
            f"git reset --hard {project_info.config.full_mode.base_commit} && git clean -fd",
            repository_directory,
        )
    )


def _commits_all_exists_locally(repository_directory: Path, commits: list[str]) -> bool:
    for commit in commits:
        if not _commit_exists_locally(repository_directory, commit):
            return False
    return True


def _commit_exists_locally(repository_directory: Path, commit: str) -> bool:
    try:
        run_command((f"git branch -a --contains {commit}", repository_directory))
        return True
    except CommandInteractionError:
        return False


def _aixcc_challenge_project_info_as_directory(
    project_info: AIxCCChallengeProject,
    cache_directory: Path,
):
    return cache_directory / Path(project_info.project_yaml.main_repo).stem


def _is_base_image(image_name: str) -> bool:
    return (OSS_FUZZ_DIRECTORY / "infra" / "base-images" / image_name).exists()


def docker_image_name(project_name: str) -> str:
    if _is_base_image(project_name):
        return f"ghcr.io/aixcc-finals/{project_name}"
    else:
        return f"aixcc-afc/{project_name}"


def check_challenge_docker_image(project_name: str) -> bool:
    return docker_image_exists(docker_image_name(project_name))


def _get_used_commits(project_info: AIxCCChallengeProject) -> list[str]:
    commits: list[str] = []
    commits.append(project_info.config.full_mode.base_commit)
    commits.extend(
        [delta_mode.ref_commit for delta_mode in project_info.config.delta_mode or []]
    )
    return commits
