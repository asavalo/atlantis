import pwd
from pathlib import Path
from unittest import mock

import pytest
from crete.commons.logging.hooks import use_logger
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import ChallengeBuildFailedError
from crete.framework.environment_pool.services.oss_fuzz import (
    OssFuzzEnvironment,
    OssFuzzEnvironmentPool,
)
from joblib import Memory
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml


def create_environment_context() -> EnvironmentContext:
    return EnvironmentContext(
        memory=Memory(),
        logging_prefix="environment_pool",
        logger=use_logger("unittest"),
        sanitizer_name="address",
    )


def create_pool_and_context(
    tmp_dir: Path, source_directory: Path, detection_toml_file: Path
) -> tuple[OssFuzzEnvironmentPool, EnvironmentContext]:
    challenge_project_detection = AIxCCChallengeProjectDetection.from_toml(
        detection_toml_file
    )

    challenge_project_yaml = AIxCCChallengeProjectYaml.from_project_name(
        challenge_project_detection.project_name
    )

    context = create_environment_context()

    return OssFuzzEnvironmentPool(
        challenge_project_directory=source_directory,
        challenge_project_detection=challenge_project_detection,
        challenge_project_yaml=challenge_project_yaml,
        max_timeout=300,
        cache_directory=tmp_dir,
    ), context


@pytest.fixture
def mock_c_pool(tmpdir_as_path: Path, detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    pool, context = create_pool_and_context(tmpdir_as_path, *detection_c_mock_cp_cpv_0)
    pool.initialize(context)
    return pool, context


@pytest.fixture
def mock_jvm_pool(
    tmpdir_as_path: Path, detection_jvm_mock_java_cpv_0: tuple[Path, Path]
):
    pool, context = create_pool_and_context(
        tmpdir_as_path, *detection_jvm_mock_java_cpv_0
    )
    pool.initialize(context)
    return pool, context


@pytest.mark.slow
def test_c_initialize(mock_c_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext]):
    pool, context = mock_c_pool
    assert pool is not None
    assert pool.use(context, "CLEAN") is not None
    pool.restore(context)


@pytest.mark.slow
def test_jvm_initialize(
    mock_jvm_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext],
):
    pool, context = mock_jvm_pool
    assert pool is not None
    assert pool.use(context, "CLEAN") is not None
    pool.restore(context)


@pytest.mark.slow
def test_initialize_with_cache(
    mock_c_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext],
):
    pool, context = mock_c_pool
    with mock.patch.object(
        OssFuzzEnvironment,
        "build",
        side_effect=ChallengeBuildFailedError(stdout=b"", stderr=b""),
    ):
        # This should not re-build the environment.
        assert pool.use(context, "CLEAN") is not None


@pytest.mark.slow
def test_use_with_clean_environment(
    mock_c_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext],
):
    pool, context = mock_c_pool
    environment = pool.use(context, "CLEAN")
    assert environment is not None

    environment.shell(context, "chown root:root /src/mock-cp-src/mock_vp.c")
    mock_vp_c = pool.source_directory / "mock_vp.c"
    assert mock_vp_c.stat().st_uid == 0

    environment.shell(context, "echo 'test' > /work/owner_changed")
    owner_changed_file = pool.work_directory / "owner_changed"
    assert owner_changed_file.stat().st_uid == 0

    environment = pool.use(context, "CLEAN")
    # Check if the original file is recovered to the original owner
    assert mock_vp_c.stat().st_uid != 0
    # Check if the created file will be removed
    assert not owner_changed_file.exists()


def test_internal_test_exists(
    tmpdir_as_path: Path, detection_c_mock_cp_cpv_0: tuple[Path, Path]
):
    pool, _context = create_pool_and_context(tmpdir_as_path, *detection_c_mock_cp_cpv_0)
    assert pool.internal_test_exists()


@pytest.mark.slow
def test_issue_1201(
    mock_c_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext],
    monkeypatch: pytest.MonkeyPatch,
):
    pool, context = mock_c_pool

    def mock_getpwuid(uid: int):
        raise KeyError("No such user")

    monkeypatch.setattr(pwd, "getpwuid", mock_getpwuid)
    pool.use(context, "CLEAN")


@pytest.mark.slow
def test_c_redirection(
    mock_c_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext],
):
    pool, context = mock_c_pool
    assert pool is not None

    debug = pool.use(context, "DEBUG")
    clean = pool.use(context, "CLEAN")
    valgrind = pool.use(context, "VALGRIND")
    call_trace = pool.use(context, "CALL_TRACE")

    assert all(
        environment is not None for environment in [debug, clean, valgrind, call_trace]
    )

    # Check if the environments are not the same
    assert debug is not clean and valgrind is not clean and call_trace is not clean


@pytest.mark.slow
def test_jvm_redirection(
    mock_jvm_pool: tuple[OssFuzzEnvironmentPool, EnvironmentContext],
):
    pool, context = mock_jvm_pool
    assert pool is not None

    debug = pool.use(context, "DEBUG")
    clean = pool.use(context, "CLEAN")
    valgrind = pool.use(context, "VALGRIND")
    call_trace = pool.use(context, "CALL_TRACE")

    assert all(
        environment is not None for environment in [debug, clean, valgrind, call_trace]
    )

    # Check if redirection is working
    # For JVM, debug -> clean, valgrind -> clean
    assert debug is clean and valgrind is clean and call_trace is not clean
