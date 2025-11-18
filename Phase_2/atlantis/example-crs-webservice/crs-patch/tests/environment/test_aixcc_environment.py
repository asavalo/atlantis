import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import pygit2
import pytest
from _pytest.fixtures import SubRequest
from crete.atoms.action import HeadAction
from crete.commons.interaction.exceptions import TimeoutExpired
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import ChallengeBuildFailedError
from crete.framework.environment.services.oss_fuzz import OssFuzzEnvironment
from crete.framework.environment_pool.models import EnvironmentType
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from joblib import Memory
from pytest_mock import MockerFixture, MockType


@pytest.fixture
def source_directory():
    with TemporaryDirectory() as temp_dir:
        # Create mock_vp.c file
        mock_vp_file = Path(temp_dir) / "mock_vp.c"
        mock_vp_file.write_text(
            """
#include <stdio.h>

int main() {
    printf("Hello from mock_vp\\n");
    return 0;
}
"""
        )

        # Initialize git repo and commit the file
        repo = pygit2.init_repository(temp_dir, False)
        index = repo.index  # pyright: ignore
        index.add_all(["."])  # pyright: ignore
        index.write()  # pyright: ignore
        tree = index.write_tree()  # pyright: # pyright: ignore
        repo.create_commit(
            "HEAD",
            pygit2.Signature("test", "test@test.com"),
            pygit2.Signature("test", "test@test.com"),
            "test",
            tree,  # pyright: ignore
            [],  # empty list for parents since this is the first commit
        )
        yield Path(temp_dir)


@pytest.fixture
def environment(mocker: MockerFixture, source_directory: Path):
    pool = MockEnvironmentPool(
        challenge_project_directory=source_directory,
        detection_toml_file=Path(""),
    )
    yield OssFuzzEnvironment(
        pool=pool,
        project_name="aixcc/c/mock-cp",
        checkout_ref="HEAD",
        max_timeout=300,
    )


@pytest.fixture
def context():
    return EnvironmentContext(
        logger=logging.getLogger("unittest"),
        logging_prefix="unittest",
        memory=Memory(verbose=0),
        sanitizer_name="address",
    )


@pytest.fixture
def mock_run_command(mocker: MockerFixture, request: SubRequest):
    patcher = mocker.patch(
        "crete.commons.interaction.functions.run_command", autospec=True
    )

    mocker.patch(
        "crete.framework.environment.services.oss_fuzz.default.run_command",
        patcher,
    )
    mocker.patch(
        "crete.framework.environment.services.oss_fuzz.valgrind.run_command",
        patcher,
    )
    return patcher


def test_timeout(
    environment: OssFuzzEnvironment,
    context: EnvironmentContext,
    mock_run_command: MockType,
):
    def mock_run_command_side_effect(*args: Any, **kwargs: Any):
        command = args[0][0] if args and args[0] else kwargs.get("command", [""])[0]
        command_parts = command.split()

        if "build_fuzzers" == command_parts[1]:
            raise TimeoutExpired(stdout=b"", stderr=b"")

        return ("", "")

    mock_run_command.side_effect = mock_run_command_side_effect

    try:
        environment.build(context)
        pytest.fail("Should raise ChallengeBuildFailedError")
    except ChallengeBuildFailedError:
        assert mock_run_command.call_count > 1  # regression timeout test
    except Exception as e:
        pytest.fail(f"Unexpected error occurred: {e}")


@pytest.mark.integration
def test_restore(environment: OssFuzzEnvironment, context: EnvironmentContext):
    # test clean up untracked files
    (environment.pool.source_directory / "foo").touch()
    environment.restore(context)
    assert not (environment.pool.source_directory / "foo").exists()

    # test clean up tracked files
    mock_vp_file = environment.pool.source_directory / "mock_vp.c"
    mock_vp_file_content = mock_vp_file.read_text()
    mock_vp_file.write_text("Changed")
    environment.restore(context)
    assert mock_vp_file.read_text() == mock_vp_file_content


@pytest.mark.integration
@pytest.mark.parametrize(
    "environment_type", ["CLEAN", "DEBUG", "CALL_TRACE", "VALGRIND"]
)
def test_environment_build(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
    environment_type: EnvironmentType,
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    environment = context["pool"].use(context, environment_type)
    assert environment is not None
    environment.restore(context)
    environment.build(context)
