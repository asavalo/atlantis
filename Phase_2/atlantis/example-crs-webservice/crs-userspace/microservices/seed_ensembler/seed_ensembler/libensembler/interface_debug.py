import json
from pathlib import Path
from typing import NoReturn
from uuid import UUID

from .constants import DEFAULT_SCORABLE_TIMEOUT_DURATION
from .fs_watcher import watch_directory
from .libfuzzer_pool import LibfuzzerPool
from .logger_wrapper import LoggerWrapper
from .models import Configuration, Harness
from .util import check_if_timeouts_scorable_in_options_file


__all__ = ['run_with_debug']


DEBUG_CONFIG_JSON = Path('debug_config.json')


logger = LoggerWrapper.getLogger(__name__)


def run_with_debug(config: Configuration) -> NoReturn:
    # Load the JSON
    with DEBUG_CONFIG_JSON.open('r', encoding='utf-8') as f:
        debug_config_json = json.load(f)

    # Collect the harness info
    harnesses = {}
    for entry in debug_config_json['harnesses']:
        timeouts_scorable = check_if_timeouts_scorable_in_options_file(
            Path(str(entry['path']) + '.options')
        )

        harness = Harness(
            entry['cp_name'],
            entry['name'],
            Path(entry['path']).resolve(),
            DEFAULT_SCORABLE_TIMEOUT_DURATION if timeouts_scorable else None,
        )
        harnesses[harness.name] = harness

    logger.info(f'Collected harnesses: {harnesses!r}')

    # Define a callback for when we see a new directory from libDeepGen
    def directory_watch_callback(path: Path, harness_id: str, script_id: int, uuid: UUID) -> None:
        harness = harnesses.get(harness_id)
        if harness is None:
            logger.warning(f'Received directory {path} from libDeepGen, for unknown harness {harness_id!r}'
                f' (we only know of {", ".join(sorted(repr(k) for k in harnesses.keys()))})')
            return

        logger.info(f'Received directory {path} from libDeepGen, for {harness_id!r}')

        pool.add_seeds_batch(path, harness, script_id, needs_feedback=True)

    # Define a (stub) callback for when the libfuzzer pool wants to
    # announce new seeds to add to the fuzzers' corpus
    def new_seeds_callback(harness: Harness, seed_paths: list[Path]) -> None:
        logger.info(f'Sending {len(seed_paths)} new seed{"s" if len(seed_paths) != 1 else ""} for {harness.name!r}')

    # Create the pool and start the directory watching
    pool = LibfuzzerPool(config, new_seeds_callback)

    logger.info(f'Watching for seeds in {config.seeds_input_dir} ...')
    watch_directory(config, directory_watch_callback, blocking=True)
