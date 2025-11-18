import logging
from pathlib import Path
from tempfile import TemporaryDirectory

from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crs_patch.functions import get_environment_context, init_environment_pool
from crs_patch.utils.challenges import construct_challenge_mode

_logger = logging.getLogger(__name__)


def test_make_crete_build_cache(detection_c_mock_c_cpv_0: tuple[Path, Path]):
    # This test is used to make sure that the crete environments cache is created correctly in sub.py
    with TemporaryDirectory(delete=False) as temp_dir:
        environments_cache_directory = Path(temp_dir)
        print(environments_cache_directory)

        environment_context = get_environment_context(
            _logger, "address", DEFAULT_CACHE_DIRECTORY
        )
        init_environment_pool(
            environment_context=environment_context,
            project_name="aixcc/c/mock-cp",
            challenge_mode=construct_challenge_mode(Path(".cache/mock-cp-src"), "full"),
            challenge_project_directory=Path(".cache/mock-cp-src"),
            crete_cache_directory=environments_cache_directory,
        )
        assert (environments_cache_directory / "aixcc" / "c" / "mock-cp").exists()
