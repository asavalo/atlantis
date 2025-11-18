from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
from multiprocessing import Queue, Value
import os
from pathlib import Path
import shutil
import threading
import traceback
from typing import NoReturn
from uuid import UUID, uuid4

from google.protobuf.message import Message
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    HARNESS_BUILDER_REQUEST_TOPIC,
    HARNESS_BUILDER_RESULT_TOPIC,
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    FUZZER_SEED_SUGGESTIONS_TOPIC,
    CRASHING_SEED_SUGGESTIONS_TOPIC,
    FUZZER_SEED_ADDITIONS_TOPIC,
)
from libatlantis.protobuf import BuildRequest, BuildRequestResponse, FuzzerLaunchAnnouncement, FuzzerSeeds, LIBFUZZER
from libatlantis.service_utils import service_callback
from libmsa import Producer
from libmsa.runner import Runner, execute_consumers
from libmsa.thread.pool import QueuePolicy

from .constants import DEFAULT_SCORABLE_TIMEOUT_DURATION
from .fs_watcher import watch_directory
from .libfuzzer_pool import LibfuzzerPool
from .logger_wrapper import LoggerWrapper
from .models import Configuration, Harness
from .util import check_if_timeouts_scorable_in_options_file, fs_copy


__all__ = ['run_with_kafka']


NODE_BASED_GROUP_ID_TEMPLATE = 'ensembler_{node_idx}'
SHARED_GROUP_ID = 'ensembler'
NUM_HB_REQUEST_THREADS = 1
NUM_HB_RESPONSE_THREADS = 1
NUM_FUZZER_LAUNCH_ANNOUNCEMENT_THREADS = 1
NUM_FUZZER_SEED_SUGGESTION_THREADS = 1
NUM_CRASHING_SEED_SUGGESTION_THREADS = 1


logger = LoggerWrapper.getLogger(__name__)


def get_node_based_group_id(config: Configuration) -> str:
    """Get the Kafka group ID."""
    if config.kafka_group_id is not None:
        return config.kafka_group_id

    group_id = os.environ.get('NODE_IDX', '0')
    return NODE_BASED_GROUP_ID_TEMPLATE.replace('{node_idx}', group_id)


@dataclass
class CpBuildInfo:
    nonce: str | None = None
    cp_name: str | None = None
    oss_fuzz_base_path: Path | None = None
    harnesses: dict[str, str] | None = None

    def ready(self) -> bool:
        return self.nonce and self.cp_name and self.oss_fuzz_base_path and self.harnesses

    def oss_fuzz_project_path(self) -> Path:
        return self.oss_fuzz_base_path / 'projects' / self.cp_name


class SeedDedupCache:
    """
    Keeps track of recently seen seeds, so that duplicates can be
    rejected. Also supports a maximum cache size, to prevent memory
    usage from growing without bound -- the least recently looked up
    seeds will be discarded first.
    """
    lock: threading.Lock
    cache: OrderedDict  # used more like a set than a dict
    max_size: int | None

    def __init__(self, max_size: int | None = None):
        self.lock = threading.Lock()
        self.cache = OrderedDict()
        self.max_size = max_size

    def look_up_and_add_seed(self, seed: bytes) -> bool:
        """
        Return True if the seed is in the cache, and False otherwise. In
        either case, add the seed to the cache.
        """
        if not self.lock.locked():
            raise RuntimeError('You must take self.lock before calling look_up_and_add_seed()')

        key = hashlib.sha1(seed).digest()

        if key in self.cache:
            # This is now the most recently seen seed, so move it to the
            # end
            self.cache.move_to_end(key)
            return True

        else:
            # Add it to the cache
            self.cache[key] = None

            # If the cache is now too large...
            if self.max_size is not None and len(self.cache) > self.max_size:
                # Remove the least recently seen seed
                self.cache.popitem(last=False)

            return False

class EnsemblerContext:
    config: Configuration
    libfuzzer_build_info: CpBuildInfo
    cache: SeedDedupCache
    pool: LibfuzzerPool
    harnesses: dict[str, Harness]
    seed_suggestions_temp_dir: Path
    producer: Producer | None

    # Somewhat complex system for synchronizing a dict[str, list[Path]]
    # across our multiple forked processes:

    # "local version": the value of libfuzzer_corpus_paths_version last
    # time we checked
    libfuzzer_corpus_paths_local_version: int
    # "version": a synchronized integer that starts at 0 and is
    # incremented every time a change is made to the dict.
    libfuzzer_corpus_paths_version: 'Value[int]'
    # "queue": not really used as a queue, per se -- this will always
    # (except for brief periods when it's being updated) contain exactly
    # one element, which is the current version of the dict. You can
    # get() to get that dict, but be sure to immediately put() it back
    # so other processes can see it too.
    libfuzzer_corpus_paths_queue: 'Queue[dict[str, list[Path]]]'
    # The cached local version of the dict. If the version field
    # indicates that nothing has changed recently, we can keep reusing
    # this instead of thrashing the queue. (I expect the int to be
    # cheaper to read than the queue.)
    _libfuzzer_corpus_paths: dict[str, list[Path]]

    def __init__(self, config: Configuration):
        self.config = config
        self.libfuzzer_build_info = CpBuildInfo()
        self.cache = SeedDedupCache(config.duplicate_seeds_cache_size)
        self.harnesses = {}
        self.seed_suggestions_temp_dir = config.temp_dir / 'seed_suggestions'
        self.harness_cache_file = config.temp_dir / 'harness_cache.jsonl'
        self.producer = None
        self.libfuzzer_corpus_paths_local_version = 0
        self.libfuzzer_corpus_paths_version = Value('Q')
        self.libfuzzer_corpus_paths_queue = Queue()
        self._libfuzzer_corpus_paths = {}

        # Initial value
        self.libfuzzer_corpus_paths_queue.put({})

        self.seed_suggestions_temp_dir.mkdir(exist_ok=True)

        # If we crashed and are being restarted, reload any previously
        # saved harness info
        if self.harness_cache_file.is_file():
            with self.harness_cache_file.open('r', encoding='utf-8') as f:
                for line in f:
                    harness = Harness.from_dict(json.loads(line))
                    self.harnesses[harness.name] = harness

        # initialize this last, to avoid race conditions
        self.pool = LibfuzzerPool(config, self.new_seeds_callback)

        watch_directory(config, self.directory_watch_callback, blocking=False)

    def get_libfuzzer_corpus_paths(self) -> dict[str, list[Path]]:
        """
        Get the latest version of the libfuzzer_corpus_paths dict.
        """
        with self.libfuzzer_corpus_paths_version.get_lock():
            if self.libfuzzer_corpus_paths_version.value > self.libfuzzer_corpus_paths_local_version:
                # Get the new dict
                self._libfuzzer_corpus_paths = self.libfuzzer_corpus_paths_queue.get()
                # Put it back into the queue right away
                self.libfuzzer_corpus_paths_queue.put(self._libfuzzer_corpus_paths)
                # Update our local version value
                self.libfuzzer_corpus_paths_local_version = self.libfuzzer_corpus_paths_version.value

        return self._libfuzzer_corpus_paths

    def set_libfuzzer_corpus_paths_entry(self, key: str, value: list[Path] | None) -> None:
        """
        Set a key-value pair in the libfuzzer_corpus_paths dict.
        """
        with self.libfuzzer_corpus_paths_version.get_lock():
            # Update both our local version value, and the shared one
            self.libfuzzer_corpus_paths_local_version = self.libfuzzer_corpus_paths_version.value = \
                self.libfuzzer_corpus_paths_version.value + 1
            # Get the current dict
            self._libfuzzer_corpus_paths = self.libfuzzer_corpus_paths_queue.get()
            # Set the new key
            self._libfuzzer_corpus_paths[key] = value
            # Put the dict back into the queue
            self.libfuzzer_corpus_paths_queue.put(self._libfuzzer_corpus_paths)

    def process_hb_request(self, message: BuildRequest) -> None:
        if message.mode == LIBFUZZER:
            self.libfuzzer_build_info.nonce = message.nonce
            self.libfuzzer_build_info.cp_name = message.cp_name
            self.libfuzzer_build_info.oss_fuzz_base_path = Path(message.oss_fuzz_path)
            logger.info(f'hb_request {self.libfuzzer_build_info}')
            self.conditional_hb_handler()

    def process_hb_response(self, message: BuildRequestResponse) -> None:
        if message.mode == LIBFUZZER:
            self.libfuzzer_build_info.harnesses = message.harnesses
            logger.info(f'hb_response {self.libfuzzer_build_info}')
            self.conditional_hb_handler()

    def conditional_hb_handler(self) -> None:
        if self.libfuzzer_build_info.ready():
            logger.info(f'conditional_handler {self.libfuzzer_build_info}')

            build_info = self.libfuzzer_build_info

            logger.info(f'Saving info about {len(self.libfuzzer_build_info.harnesses)} libfuzzer harnesses')

            for harness_id, harness_path in self.libfuzzer_build_info.harnesses.items():
                timeouts_scorable = check_if_timeouts_scorable_in_options_file(
                    build_info.oss_fuzz_project_path() / f'{harness_id}.options'
                )

                harness = Harness(
                    build_info.cp_name,
                    harness_id,
                    Path(harness_path),
                    DEFAULT_SCORABLE_TIMEOUT_DURATION if timeouts_scorable else None,
                )

                self.harnesses[harness_id] = harness

                # Also save the harness info to a file, in case we crash and
                # need to recover it when we restart
                with self.harness_cache_file.open('a', encoding='utf-8') as f:
                    json.dump(harness.to_dict(), f)
                    f.write('\n')

    def process_fuzzer_launch_announcement(self, message: FuzzerLaunchAnnouncement) -> None:
        if message.mode == 'libfuzzer':
            logger.info(f'Activating libfuzzer-fallback mode for "{message.harness_id}"')
            self.set_libfuzzer_corpus_paths_entry(
                message.harness_id,
                [Path(p) for p in message.corpus_paths],
            )
        else:
            logger.info(f'Deactivating libfuzzer-fallback mode for "{message.harness_id}"')
            self.set_libfuzzer_corpus_paths_entry(
                message.harness_id,
                None,
            )

    def process_seed_suggestion(self, message: FuzzerSeeds) -> None:
        if not message.data:
            logger.info('No seed data')
            return

        harness = self.harnesses.get(message.harness_id)
        if harness is None:
            logger.info(f'Received seed suggestion message with {len(message.data)} seeds,'
                f' for unknown harness {message.harness_id!r}'
                f' (we only know of {", ".join(sorted(repr(k) for k in self.harnesses.keys()))})')
            return

        # log the seed for evaluation
        if self.config.verbose:
            logger.event('seed_suggestion', {
                'harness_id': message.harness_id,
                'origin': message.origin,
                'data': [
                    hashlib.sha1(d).hexdigest()
                    for d in message.data
                ],
            })
        else:
            logger.event('seed_suggestion', {
                'harness_id': message.harness_id,
                'origin': message.origin,
                'data': f'<{len(message.data)} seeds>',
            })

        # Reject any duplicate seeds
        duplicates = set()
        with self.cache.lock:
            for i, seed in enumerate(message.data):
                if self.cache.look_up_and_add_seed(seed):
                    if self.config.verbose:
                        logger.info(f'Seed {hashlib.sha1(seed).hexdigest()} is a duplicate')
                    duplicates.add(i)

        if len(duplicates) == len(message.data):
            if self.config.verbose:
                logger.info(f'All {len(duplicates)} seeds from this message were duplicates')
            return

        temp_dir = self.seed_suggestions_temp_dir / str(uuid4())
        temp_dir.mkdir()

        for i, seed in enumerate(message.data):
            if i not in duplicates:
                (temp_dir / f'{i:06d}.bin').write_bytes(seed)

        self.pool.add_seeds_batch(temp_dir, harness, None, needs_feedback=False)

    def directory_watch_callback(self, path: Path, harness_id: str, script_id: int, uuid: UUID) -> None:
        harness = self.harnesses.get(harness_id)
        if harness is None:
            logger.warning(f'Received directory {path} from libDeepGen, for unknown harness {harness_id!r}'
                f' (we only know of {", ".join(sorted(repr(k) for k in self.harnesses.keys()))})')
            return

        if self.config.verbose:
            logger.info(f'Received directory {path} from libDeepGen, for {harness_id!r}')

        # Check for any duplicate seeds, and collect data for logging
        seed_datas = []
        any_new_seeds = False
        with self.cache.lock:
            for seed_path in path.iterdir():
                seed = seed_path.read_bytes()
                seed_datas.append(seed)
                if self.cache.look_up_and_add_seed(seed):
                    if self.config.verbose:
                        logger.info(f'Seed {hashlib.sha1(seed).hexdigest()} is a duplicate')
                    seed_path.unlink(missing_ok=True)
                else:
                    any_new_seeds = True

        # Log the seeds for evaluation
        if self.config.verbose:
            logger.event('ldg_directory_recv', {
                'harness_id': harness_id,
                'origin': f'libDeepGen {script_id}',
                'data': [
                    hashlib.sha1(seed).hexdigest()
                    for seed in seed_datas
                ],
            })
        else:
            logger.event('ldg_directory_recv', {
                'harness_id': harness_id,
                'origin': f'libDeepGen {script_id}',
                'data': f'<{len(seed_datas)} seeds>',
            })

        if not any_new_seeds:
            if not seed_datas:
                logger.info('The folder from libDeepGen was empty')
            else:
                logger.info(f'All {len(seed_datas)} seeds from this libDeepGen batch were duplicates')

            shutil.rmtree(path, ignore_errors=True)
            return

        self.pool.add_seeds_batch(path, harness, script_id, needs_feedback=True)

    def new_seeds_callback(self, harness: Harness, seed_paths: list[Path]) -> None:
        # NOTE: this is called from each (forked) worker process, NOT
        # from the main/original process.

        # This is why I initialize the Producer lazily here -- so that
        # each worker process will get its own independent Producer
        # instead of forking N copies of a single one, which I imagine
        # could potentially greatly confuse the Kafka broker.

        corpus_paths_for_harness = self.get_libfuzzer_corpus_paths().get(harness.name)
        if corpus_paths_for_harness is None:
            logger.info(f'Sending a batch of {len(seed_paths)} seeds for {harness.name!r} to Kafka seed additions topic')

            if self.producer is None:
                self.producer = Producer(KAFKA_SERVER_ADDR, FUZZER_SEED_ADDITIONS_TOPIC)

            message = FuzzerSeeds()
            message.harness_id = harness.name
            message.origin = 'seed_ensembler'
            message.data.extend(fp.read_bytes() for fp in seed_paths)

            self.producer.send_message(message)

        else:
            logger.info(f'Writing a batch of {len(seed_paths)} seeds for {harness.name!r} to {len(corpus_paths_for_harness)} corpus directories')

            for fp in seed_paths:
                new_name = hashlib.sha1(fp.read_bytes()).hexdigest()
                for corpus_path in corpus_paths_for_harness:
                    try:
                        fs_copy(fp, corpus_path / new_name)
                    except Exception:
                        logger.error(traceback.format_exc())


@service_callback(logger, BuildRequest, 'harness build request')
def process_hb_request(
    input_message: BuildRequest, thread_id: int, context: EnsemblerContext
) -> list[Message]:
    context.process_hb_request(input_message)
    return []


@service_callback(logger, BuildRequestResponse, 'harness build response')
def process_hb_response(
    input_message: BuildRequestResponse, thread_id: int, context: EnsemblerContext
) -> list[Message]:
    context.process_hb_response(input_message)
    return []


@service_callback(logger, FuzzerLaunchAnnouncement, 'fuzzer launch announcement')
def process_fuzzer_launch_announcement(
    input_message: BuildRequestResponse, thread_id: int, context: EnsemblerContext
) -> list[Message]:
    context.process_fuzzer_launch_announcement(input_message)
    return []


@service_callback(logger, FuzzerSeeds, 'fuzzer seed suggestion', log=False)
def process_fuzzer_seed_suggestion(
    input_message: FuzzerSeeds, thread_id: int, context: EnsemblerContext
) -> list[Message]:
    # Identical to process_crashing_seed_suggestion() -- only difference
    # is that we register for this topic with per-node Kafka group IDs
    context.process_seed_suggestion(input_message)
    return []


@service_callback(logger, FuzzerSeeds, 'crashing seed suggestion', log=False)
def process_crashing_seed_suggestion(
    input_message: FuzzerSeeds, thread_id: int, context: EnsemblerContext
) -> list[Message]:
    # Identical to process_fuzzer_seed_suggestion() -- only difference
    # is that we register for this topic with a shared Kafka group ID
    context.process_seed_suggestion(input_message)
    return []


def run_with_kafka(config: Configuration) -> NoReturn:
    context = EnsemblerContext(config)

    node_based_group_id = get_node_based_group_id(config)

    hb_request_contexts = [context] * NUM_HB_REQUEST_THREADS
    hb_request_runner = Runner(
        HARNESS_BUILDER_REQUEST_TOPIC,
        BuildRequest,
        node_based_group_id,
        None,
        NUM_HB_REQUEST_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_hb_request,
        hb_request_contexts,
    )

    hb_response_contexts = [context] * NUM_HB_RESPONSE_THREADS
    hb_response_runner = Runner(
        HARNESS_BUILDER_RESULT_TOPIC,
        BuildRequestResponse,
        node_based_group_id,
        None,
        NUM_HB_RESPONSE_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_hb_response,
        hb_response_contexts,
    )

    launch_ann_contexts = [context] * NUM_FUZZER_LAUNCH_ANNOUNCEMENT_THREADS
    launch_ann_runner = Runner(
        FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
        FuzzerLaunchAnnouncement,
        node_based_group_id,
        None,
        NUM_FUZZER_LAUNCH_ANNOUNCEMENT_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_launch_announcement,
        launch_ann_contexts,
    )

    fuzzer_seed_suggestion_contexts = [context] * NUM_FUZZER_SEED_SUGGESTION_THREADS
    fuzzer_seed_suggestion_runner = Runner(
        FUZZER_SEED_SUGGESTIONS_TOPIC,
        FuzzerSeeds,
        node_based_group_id,
        None,
        NUM_FUZZER_SEED_SUGGESTION_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_fuzzer_seed_suggestion,
        fuzzer_seed_suggestion_contexts,
    )

    crashing_seed_suggestion_contexts = [context] * NUM_CRASHING_SEED_SUGGESTION_THREADS
    crashing_seed_suggestion_runner = Runner(
        CRASHING_SEED_SUGGESTIONS_TOPIC,
        FuzzerSeeds,
        SHARED_GROUP_ID,
        None,
        NUM_CRASHING_SEED_SUGGESTION_THREADS,
        QueuePolicy.ROUND_ROBIN,
        process_crashing_seed_suggestion,
        crashing_seed_suggestion_contexts,
    )

    consumers = [
        hb_request_runner.execute_thread_pool(),
        hb_response_runner.execute_thread_pool(),
        launch_ann_runner.execute_thread_pool(),
        fuzzer_seed_suggestion_runner.execute_thread_pool(),
        crashing_seed_suggestion_runner.execute_thread_pool(),
    ]
    execute_consumers(consumers)
