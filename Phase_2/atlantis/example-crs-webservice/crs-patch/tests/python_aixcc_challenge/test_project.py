from pathlib import Path

from pytest_mock.plugin import MockerFixture
from python_aixcc_challenge.project.functions import (
    prepare_aixcc_challenge_projects_from_detection_files,
)
from python_aixcc_challenge.project.models import AIxCCChallengeProject


def test_prepare_projects_from_detection_toml_files(
    mocker: MockerFixture,
    benchmark_directory: Path,
    cache_directory: Path,
):
    detection_toml_files = [
        benchmark_directory / "full" / "official-c-mock-cp-cpv-0-full.toml",
        benchmark_directory / "full" / "official-c-mock-cp-cpv-1-full.toml",
        benchmark_directory / "full" / "custom-jvm-jenkins-cpv-0-full.toml",
        benchmark_directory / "full" / "custom-c-babynote-cpv-0-full.toml",
    ]

    expected_project_directories = [
        Path("mock-cp-src"),
        Path("mock-cp-src"),
        Path("cp-java-jenkins-source"),
        Path("cp-user-babynote-src"),
    ]

    mocker.patch(
        "python_aixcc_challenge.project.functions._build_aixcc_challenge_projects",
        _build_aixcc_challenge_projects,
    )

    project_directories = prepare_aixcc_challenge_projects_from_detection_files(
        detection_toml_files, cache_directory
    )

    assert [
        project_directory.relative_to(cache_directory)
        for project_directory in project_directories
    ] == expected_project_directories


def _build_aixcc_challenge_projects(
    projects: list[AIxCCChallengeProject], cache_directory: Path
):
    return None
