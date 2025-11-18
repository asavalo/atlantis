import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from _pytest.config import Config
from _pytest.config.argparsing import Parser
from _pytest.fixtures import SubRequest
from aider.coders import Coder
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from pytest import Metafunc
from pytest_mock.plugin import MockerFixture
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.functions import (
    prepare_aixcc_challenge_projects_from_detection_files,
)
from vcr import VCR
from vcr.serialize import Request

from tests.common.portable_yaml_serializer import PortableYamlSerializer
from tests.common.vcr import install_patchers

_BENCHMARK_DIRECTORY = Path(__file__).parent.parent / "scripts" / "benchmark"
_TEST_DATA_DIRECTORY = Path(__file__).parent / "test_data"
_SMALL_PROJECTS = ["mock_cp", "mock_java", "mock_c", "integration_test"]


def pytest_addoption(parser: Parser):
    parser.addoption(
        "--build",
        action="store_true",
        default=False,
        help="Build test data using online LLM API",
    )

    parser.addoption(
        "--no-cache",
        action="store_true",
        default=False,
        help="Build test data from scratch",
    )

    parser.addoption(
        "--disable-force-prepare",
        action="store_true",
        default=False,
        help="Disable force prepare challenge projects",
    )


def pytest_runtest_setup(item: pytest.Item):
    prefix = "detection_"

    fixture_names = cast(list[str], item.fixturenames)  # type: ignore
    for fixturename in fixture_names:
        if fixturename.startswith(prefix):
            detection_file = _detection_file_from_fixture_name(fixturename, prefix)

            challenge_project_directory = (
                prepare_aixcc_challenge_projects_from_detection_files(
                    [detection_file],
                    DEFAULT_CACHE_DIRECTORY,
                    disable_force_prepare=False,
                )[0]
            )
            checkout_ref = AIxCCChallengeProjectDetection.from_toml(
                detection_file
            ).mode.checkout_ref()

            subprocess.run(
                ["git", "reset", "--hard", checkout_ref],
                cwd=challenge_project_directory,
                check=True,
            )


def pytest_runtest_call(item: Any):
    for name in item.fixturenames:
        if name.startswith("detection_"):
            assert_test_is_marked_as_slow(item, name)


def assert_test_is_marked_as_slow(item: Any, fixture_name: str):
    marked = (
        item.get_closest_marker("slow")
        or item.get_closest_marker("integration")
        or item.get_closest_marker("skip")
    )
    if not marked and is_big_project(fixture_name):
        pytest.fail(
            f"For non-slow tests, we only allow to use {_SMALL_PROJECTS}. Use @slow or @integration to mark this test as slow."
        )


def is_big_project(fixture_name: str) -> bool:
    for keyword in _SMALL_PROJECTS:
        if keyword in fixture_name:
            return False
    else:
        return True


def pytest_generate_tests(metafunc: Metafunc):
    if metafunc.definition.get_closest_marker("skip"):
        return

    prefix = "detection_"

    filtered_fixture_names = list(
        filter(lambda name: name.startswith(prefix), metafunc.fixturenames)
    )

    detection_files = [
        _detection_file_from_fixture_name(fixture_name, prefix)
        for fixture_name in filtered_fixture_names
    ]

    challenge_project_directories = (
        prepare_aixcc_challenge_projects_from_detection_files(
            detection_files,
            DEFAULT_CACHE_DIRECTORY,
            disable_force_prepare=bool(
                metafunc.config.getoption("disable_force_prepare")
            ),
        )
    )

    for fixture_name, challenge_project_directory, detection_file in zip(
        filtered_fixture_names, challenge_project_directories, detection_files
    ):
        metafunc.parametrize(
            fixture_name,
            [
                (
                    challenge_project_directory,
                    detection_file,
                )
            ],
        )


def _detection_file_from_fixture_name(
    fixture_name: str,
    prefix: str = "detection_",
    benchmark_directory: Path = _BENCHMARK_DIRECTORY,
) -> Path:
    name = fixture_name.replace(prefix, "", 1).replace("_", "-")

    if fixture_name.endswith("_delta"):
        name = name[:-6]
        target = f"full/*-{name}-delta.toml"
    elif fixture_name.endswith("_sarif_only"):
        name = name[:-11]
        target = f"full/*-{name}-sarif-only.toml"
    elif fixture_name.endswith("_sarif_pov"):
        name = name[:-10]
        target = f"full/*-{name}-sarif-pov.toml"
    else:
        target = f"full/*-{name}-full.toml"

    detection_file = next(benchmark_directory.glob(target), None)
    if detection_file is None:
        raise FileNotFoundError(
            f"No detection file found for a fixture named {fixture_name}"
        )
    return detection_file


def mock_aider_get_platform_info(self: Coder) -> str:
    return "- Platform: Linux-5.15.0-113-generic-x86_64-with-glibc2.35\
\n- Shell: SHELL=/bin/bash\
\n- Current date/time: 2024-01-01T00:00:00+00"


@pytest.fixture(autouse=True)
def ensure_deterministic(request: SubRequest, mocker: MockerFixture):
    mocker.patch(
        "aider.coders.base_coder.Coder.get_platform_info",
        mock_aider_get_platform_info,
    )

    # Ensure deterministic JSON serialization
    original_dumps = json.dumps

    def sorted_dumps(*args: object, **kwargs: object) -> str:
        kwargs.setdefault("sort_keys", True)
        return original_dumps(*args, **kwargs)

    mocker.patch(
        "json.dumps",
        lambda *args, **kwargs: sorted_dumps(  # pyright: ignore[reportUnknownLambdaType, reportUnknownArgumentType]
            *args,  # pyright: ignore[reportUnknownArgumentType]
            **kwargs,  # pyright: ignore[reportUnknownArgumentType]
        ),
    )

    # Make ripgrep deterministic using RIPGREP_CONFIG_FILE
    os.environ["RIPGREP_CONFIG_FILE"] = str(
        _TEST_DATA_DIRECTORY.absolute() / "ripgreprc"
    )


def pytest_recording_configure(config: Config, vcr: VCR):
    vcr.register_serializer("yaml", PortableYamlSerializer())  # type: ignore


@pytest.fixture(scope="module")
def vcr_config():
    install_patchers()

    def before_record_request(request: Request):
        # Try to ignore the request to download embeddings
        if request.path == "/embeddings":  # pyright: ignore[reportUnknownMemberType]
            return None

        if hasattr(request, "uri") and os.environ.get("LITELLM_API_BASE"):
            request.uri = request.uri.replace(  # pyright: ignore[reportUnknownMemberType]
                os.environ["LITELLM_API_BASE"], "https://llm-base"
            )

        return request

    return {
        "before_record_request": before_record_request,
        "filter_headers": ["authorization", "api-key", "x-api-key", "host"],
        # Remove host from match_on because host can be different based on config
        "match_on": ["method", "scheme", "path", "query", "body"],
        # To avoid recording for docker
        "ignore_localhost": True,
        # This is used for downloading vmlinux.o
        "ignore_hosts": ["drive.google.com", "raw.githubusercontent.com"],
    }


@pytest.fixture
def cache_directory():
    return DEFAULT_CACHE_DIRECTORY


@pytest.fixture
def benchmark_directory() -> Path:
    return _BENCHMARK_DIRECTORY


@pytest.fixture
def tmpdir_as_path(tmpdir: Path) -> Path:
    return Path(str(tmpdir))
