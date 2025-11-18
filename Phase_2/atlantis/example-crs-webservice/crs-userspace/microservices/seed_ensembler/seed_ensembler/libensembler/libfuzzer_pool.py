from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
# from multiprocessing.dummy import Process, Queue
from multiprocessing import Process, Queue
import os
from pathlib import Path
from queue import Empty
import random
import shutil
import traceback
from typing import Callable, Iterator, TypeAlias

from .libfuzzer_handler import (
    AbstractLibfuzzerEnvironment,
    DockerLibfuzzerEnvironment,
    ChrootLibfuzzerEnvironment,
    LibfuzzerMergeResult,
)
from .libfuzzer_result import LibfuzzerFailure, Sanitizer
from .logger_wrapper import LoggerWrapper
from .models import Configuration, Harness
from .models_shared import SeedsBatchFeedback
from .vapi_submit import VapiSubmitter, is_vapi_enabled


NewSeedsCallback: TypeAlias = Callable[[Harness, list[Path]], None]


WORKER_QUEUE_MAX_SIZE = 1024
SUBMIT_QUEUE_MAX_SIZE = 8192

# Each individual seed will have this long to execute before being killed
PER_SEED_TIMEOUT = 1.0
# Each libfuzzer-merge process will have (num seeds) * (this) before being killed
OVERALL_TIMEOUT_SEED_FACTOR = 0.5
# Minimum timeout value for the libfuzzer-merge processes, if there are very few seeds
MIN_OVERALL_TIMEOUT = 10.0

MAIN_QUEUE_GET_TIMEOUT = 0.2
SLOW_SEEDS_QUEUE_GET_TIMEOUT = 0.2

TIMEOUT_BUFFER_FACTOR = 1.4


logger = LoggerWrapper.getLogger(__name__)


@dataclass
class SeedsBatch:
    path: Path
    harness: Harness
    script_id: int | None
    needs_feedback: bool


@dataclass
class SlowSeed:
    path: Path
    harness: Harness


class Worker(Process):
    """A process/thread in the libfuzzer-merge process/thread pool."""
    proc_i: int
    input_queue: Queue
    output_queue: Queue | None
    slow_seeds_queue: Queue
    coverage_seeds_dir: Path
    crashing_seeds_dir: Path
    temp_dir: Path
    feedback_output_dir: Path
    docker_image: str | None
    new_seeds_callback: NewSeedsCallback
    verbose: bool

    def __init__(
        self,
        proc_i: int,
        input_queue: Queue,
        output_queue: Queue | None,
        slow_seeds_queue: Queue,
        coverage_seeds_dir: Path,
        crashing_seeds_dir: Path,
        temp_dir: Path,
        feedback_output_dir: Path,
        docker_image: str | None,
        new_seeds_callback: NewSeedsCallback,
        *,
        verbose: bool = False,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.proc_i = proc_i
        self.input_queue = input_queue
        self.output_queue = output_queue
        self.slow_seeds_queue = slow_seeds_queue
        self.coverage_seeds_dir = coverage_seeds_dir
        self.crashing_seeds_dir = crashing_seeds_dir
        self.crashing_seeds_dir_size = 0
        self.temp_dir = temp_dir
        self.feedback_output_dir = feedback_output_dir
        self.docker_image = docker_image
        self.new_seeds_callback = new_seeds_callback
        self.verbose = verbose

    @staticmethod
    def make_flat_symlink_tree(original_dir: Path, new_dir: Path, *, as_if: Path | None = None) -> None:
        """
        Add symlinks to `new_dir` that point to all files and folders
        currently in `original_dir`.

        `new_dir` is assumed to initially either be empty or not exist
        at all. This function is NOT recursive, so if `original_dir` has
        any subdirectories, `new_dir` will contain symlinks to those
        folders directly.

        If `as_if` is not None, the symlinks targets will be set "as if"
        `original_dir` was actually that dir. If those two directories
        are different, this will generally lead to broken symlinks, but
        this feature can be used to create symlinks that are valid in a
        Docker container.
        """
        if as_if is not None:
            as_if = as_if.resolve()

        new_dir.mkdir(exist_ok=True)

        for item in original_dir.iterdir():
            src = new_dir / item.name
            dst = item.resolve()

            if as_if is not None:
                dst = as_if / dst.relative_to(original_dir)

            src.symlink_to(dst)

    def get_queue_item(self) -> SeedsBatch | SlowSeed:
        """
        Retrieve either a batch of seeds from the main input queue, or
        -- if the input queue is empty -- a slow seed from the
        slow-seeds queue.
        """
        while True:
            try:
                return self.input_queue.get(timeout=MAIN_QUEUE_GET_TIMEOUT)
            except Empty:
                # This exception is really poorly named. It doesn't
                # necessarily mean the queue was actually empty: it can
                # also just mean that the queue was *busy* because other
                # processes had it locked for writing. So we need to
                # check whether it was *actually* empty, since that
                # affects how we want to proceed.
                # And the .empty() function has the same problem!
                # So we SPECIFICALLY need to do it this way:
                if self.input_queue.qsize() == 0:
                    # It is truly empty. While we wait, we can try to
                    # pull a seed from the slow-seeds queue
                    try:
                        return self.slow_seeds_queue.get(timeout=SLOW_SEEDS_QUEUE_GET_TIMEOUT)
                    except Empty:
                        # If we can't quickly/easily get a slow seed,
                        # we should loop back to the top and check the
                        # main queue again, in case something got added
                        continue
                else:
                    # Not actually empty -- try again
                    continue

    def run(self) -> None:
        """Main entrypoint for the thread/process"""
        self.coverage_seeds_dir.mkdir(exist_ok=True)
        self.crashing_seeds_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)
        self.feedback_output_dir.mkdir(exist_ok=True)

        libfuzzer_root = self.temp_dir / 'libfuzzer_root'
        artifact_prefix = self.temp_dir / 'artifact_prefix'

        env: AbstractLibfuzzerEnvironment
        if self.docker_image is None:
            env = ChrootLibfuzzerEnvironment(
                libfuzzer_root,
                artifact_prefix,
                False,
                verbose=self.verbose,
            )
        else:
            env = DockerLibfuzzerEnvironment(
                libfuzzer_root,
                artifact_prefix,
                self.docker_image,
                verbose=self.verbose,
            )

        env.set_up()

        while True:
            try:
                item = self.get_queue_item()

                with logger.session():
                    if isinstance(item, SeedsBatch):
                        self.process_seeds_batch(env, item)
                    else:  # (SlowSeed)
                        self.process_slow_seed(env, item)

            except Exception:
                logger.error(traceback.format_exc())

    def send_to_submission_worker(self, harness: Harness, failures: list[LibfuzzerFailure]) -> None:
        """
        Send a set of failed seeds (crashes/timeouts) to the
        SubmissionWorker process, if possible. If VAPI is disabled and
        there's no SubmissionWorker process, clean up the seeds
        ourselves.
        """
        # Early exit (no need to print "skipping submission" logs if
        # there's nothing here at all)
        if not failures:
            return

        # Log the crashes and remove ones pointing to nonexistent files
        failures_to_remove = set()
        for failure in failures:
            if failure.input_path is None:
                logger.warning(f"Skipping submission of {failure} for {harness} because it doesn't have a file path")
                failures_to_remove.add(id(failure))
                continue
            try:
                seed_data = failure.input_path.read_bytes()
            except FileNotFoundError:
                logger.warning(f"Skipping submission of {failure} for {harness} because the file doesn't exist")
                failures_to_remove.add(id(failure))
                continue

            logger.event('submission', {
                'harness_id': harness.name,
                'sanitizer_output': failure.summary.decode('utf-8', errors='replace') if failure.summary is not None else None,
                'data': base64.b64encode(seed_data).decode(),
                'is_timeout': failure.is_timeout(),  # code dup hm
            })

        failures = [f for f in failures if id(f) not in failures_to_remove]

        if self.output_queue is None:
            logger.info(f"Skipping submission of {failures} for {harness} because there's no output queue")

            # And also delete the seeds manually, since normally the
            # submission worker would be responsible for that
            for failure in failures:
                failure.input_path.unlink(missing_ok=True)

            return

        # If there aren't any actual crashes to submit, don't waste time
        # trying to put the result in the queue
        if not failures:
            return

        logger.info(f'Sending {failures} to submission worker for {harness}')

        self.output_queue.put((harness, failures))

    def map_failures_to_inputs(self, batch: SeedsBatch, result: LibfuzzerMergeResult) -> Iterator[LibfuzzerFailure]:
        """
        Given a batch of input seeds, and the result of running
        libfuzzer-merge, attempt to determine which input seeds were
        responsible for which failures. Yield the same LibfuzzerFailure
        objects, but with their path attributes updated to point to the
        original seeds.

        Any failures that can't be mapped to a corresponding input seed
        are logged as a warning and then discarded.
        """
        batch_seed_paths = list(batch.path.iterdir())

        sha1_to_host_path: dict[str, Path] = {}
        batch_seeds_cache: dict[Path, bytes] = {}
        for failure in result.failures:
            # Our goal here is to do our best to ensure that
            # "failure.input_path" points to one of the files in the
            # batch's directory. If we can't do that, we unfortunately
            # wil need to discard the seed.

            # In some cases, "failure.input_path" has already been
            # determined from the libfuzzer output. That's the easy
            # case, where we don't really have to do anything.

            if failure.input_path is not None:
                yield failure
                continue

            # But there are known cases where libfuzzer doesn't print
            # that path. If that happens, we need to try other
            # approaches.

            # First, a simple heuristic: if the batch only contains one
            # seed, and libfuzzer only crashed once, it was PROBABLY due
            # to that seed. This heuristic is a little risky, since if a
            # crashing seed somehow snuck into our main corpus, this
            # condition could start triggering inappropriately. Overall,
            # though, this is probably a worthwhile trade-off.
            if len(result.failures) == 1 and len(batch_seed_paths) == 1:
                failure.input_path = batch_seed_paths[0]
                yield failure
                continue

            # At this point, our only remaining option is to attempt to
            # figure it out from "failure.output_path", which is the
            # file that libfuzzer wrote when it detected the failure.

            # It's unlikely that that *also* isn't available, but just
            # in case:
            if failure.output_path is None:
                logger.warning('Discarding a seed that has no input *and* no output path')
                continue

            # Anyway, the output path *should* end with a SHA-1 of the
            # seed data, and that's how we'll try to find the
            # corresponding input seed for it. Unfortunately, in
            # practice, this seems to often be wrong for some reason.
            # For example, libfuzzer often attributes crashes to
            # "da39a3ee5e6b4b0d3255bfef95601890afd80709", which is the
            # hash of the empty string. I've verified that in those
            # cases, the ensembler is *not* providing empty input seeds,
            # and empty inputs shouldn't be causing crashes even if it
            # was. Anecdotally, I've even seen this happen occasionally
            # in manual testing using completely benign inputs.
            # libfuzzer just seems to be fundamentally unreliable in
            # this way.

            # Actually, let's check for that and just discard it
            # immediately if that's what's happening.
            if failure.output_path.name.endswith('da39a3ee5e6b4b0d3255bfef95601890afd80709'):
                logger.warning('Discarding a failure attributed to an empty seed')
                continue

            # Anyway, while libfuzzer's output is often wrong, it's not
            # *always* wrong, so we should still at least try to use it.

            # For robustness, we can try using both the filename and the
            # file contents, in case one or the other doesn't work out.

            # First, gather what info we can from the output path:
            target_sha1s = {failure.output_path.name[-40:]}
            output_file_len = None
            try:
                output_file_data = failure.output_path.read_bytes()
                target_sha1s.add(hashlib.sha1(output_file_data).hexdigest())
                output_file_len = len(output_file_data)
            except FileNotFoundError:
                pass

            # It's possible that libfuzzer just hashed and dumped a
            # prefix of the crashing seed, rather than the entire thing.
            # But if that happened, it's also possible that the prefix
            # is short enough that it could match multiple seeds. So if
            # we see any seeds that match as a prefix, keep track of
            # them and maybe they'll be helpful later.
            prefix_matches = []

            for target_sha1 in target_sha1s:
                # Compare to files we've already calculated hashes of
                failure.input_path = sha1_to_host_path.get(target_sha1)

                if failure.input_path is None:
                    # Calculate hashes of more files, and compare it to
                    # those
                    for check_file in batch.path.iterdir():
                        check_data = batch_seeds_cache.get(check_file)
                        if check_data is None:
                            check_data = batch_seeds_cache[check_file] = check_file.read_bytes()

                        check_sha1 = hashlib.sha1(check_data).hexdigest()
                        sha1_to_host_path[check_sha1] = check_file

                        if check_sha1 == target_sha1:
                            failure.input_path = check_file
                            break

                        if (output_file_len is not None
                            and output_file_len < len(check_data)
                            and hashlib.sha1(check_data).hexdigest() == target_sha1
                        ):
                            prefix_matches.append(check_file)
                            # (Intentionally not breaking here)

                if failure.input_path is not None:
                    break

            if failure.input_path is None and len(prefix_matches) == 1:
                # No full matches, but exactly one seed matched as a
                # prefix? Good enough for me
                failure.input_path = prefix_matches[0]

            if failure.input_path is None:
                # We weren't able to identify the seed that caused this
                # failure. That's not good, but our only real option
                # here is to just log a warning and skip it
                logger.warning("Couldn't identify which seed caused a crash"
                    f' (libfuzzer output filename was "{failure.output_path}";'
                    f' input files were {sha1_to_host_path!r};'
                    f' prefix matches were {prefix_matches})')
            else:
                yield failure

    def process_seeds_batch(
        self,
        env: AbstractLibfuzzerEnvironment,
        batch: SeedsBatch,
    ) -> None:
        """Process a new batch of seeds"""
        temp_coverage_dir = self.temp_dir / 'coverage_seeds'

        try:
            shutil.rmtree(temp_coverage_dir)
        except FileNotFoundError:
            pass

        if self.verbose:
            logger.info(f'Processing {batch}')

        harness_coverage_seeds_dir = self.coverage_seeds_dir / batch.harness.name
        harness_coverage_seeds_dir.mkdir(exist_ok=True)

        num_existing_seeds = len(list(harness_coverage_seeds_dir.iterdir()))
        num_new_seeds = len(list(batch.path.iterdir()))
        num_total_seeds = num_existing_seeds + num_new_seeds

        invoc = env.prepare_invocation(
            batch.harness.path_in_out_dir,
            [temp_coverage_dir, batch.path],
            [harness_coverage_seeds_dir],
            overall_timeout=max(MIN_OVERALL_TIMEOUT, num_total_seeds * OVERALL_TIMEOUT_SEED_FACTOR),
            per_seed_timeout=PER_SEED_TIMEOUT,
        )

        # We want the symlinks in this symlink tree to point to
        # harness_coverage_seeds_dir, but they have to be valid in the
        # *guest* environment. So we mounted that directory using
        # AbstractLibfuzzerEnvironment's "other_mount_dirs" feature, and
        # now we'll create the symlink tree to point to paths rooted at
        # the corresponding guest mount point.

        self.make_flat_symlink_tree(
            harness_coverage_seeds_dir,
            temp_coverage_dir,
            as_if=invoc.mounts.other_mount_dirs_guest[0],
        )

        invoc.mounts.artifact_prefix_host.mkdir(exist_ok=True)

        result = invoc.run_merge()

        # First, move the new coverage seeds to the main coverage dir,
        # so they can start propagating to the rest of the system ASAP

        new_seeds = []
        for file in temp_coverage_dir.iterdir():
            if not file.is_symlink():
                src = file
                dst = harness_coverage_seeds_dir / file.name

                # When libfuzzer merges a seed into the first directory
                # (temp_coverage_dir), it names it based on a SHA1 of its
                # contents. So assuming no SHA1 collisions, any two
                # files in harness_coverage_seeds_dir with the same name
                # will necessarily have the same data, and can be
                # skipped.
                if not dst.is_file():
                    new_seeds.append(dst)

                    # We should also assume that the two paths may be on
                    # different filesystems. So we do something similar
                    # to the logic of shutil.move(), except that
                    # deleting the original file is optional
                    # (os.rename() does it but shutil.copy() doesn't),
                    # since the whole directory is going to get rmtree'd
                    # soon anyway.
                    try:
                        os.rename(src, dst)
                    except OSError:
                        shutil.copy(src, dst)
                    except FileExistsError:
                        # Another process must've created the file after
                        # we checked that it didn't exist (race
                        # condition). That's fine, just skip it then.
                        pass

        # Next, move the crashing/timeout seeds to the crashing-seeds
        # dir, so they don't get deleted in the cleanup we're about to
        # perform (note: either the submission worker will delete them
        # after it's done submitting them, or we'll detect that there's
        # no submission worker and delete them ourselves)
        new_failures = []
        for failure in self.map_failures_to_inputs(batch, result):
            # Now we can do the actual move, and update
            # failure.input_path a second time to point to its updated
            # location.

            src = failure.input_path  # note: map_failures_to_inputs() guarantees this is not None
            dst = self.crashing_seeds_dir / f'{self.crashing_seeds_dir_size:09d}.bin'
            self.crashing_seeds_dir_size += 1

            try:
                os.rename(src, dst)
            except FileNotFoundError:
                # This can happen if we (somehow) get multiple failures
                # reported for the same seed. After it gets moved the
                # first time, it'll already be gone when we try to move
                # it the second time. To be robust, we should just
                # discard this seed
                logger.warning(f"Couldn't copy {src} because it doesn't exist (duplicate failure detected?)")
                continue
            except OSError:
                shutil.copy(src, dst)

            failure.input_path = dst
            new_failures.append(failure)

        result.failures = new_failures

        # Clean up
        shutil.rmtree(batch.path)
        shutil.rmtree(temp_coverage_dir)
        shutil.rmtree(invoc.mounts.artifact_prefix_host)

        if batch.needs_feedback:
            # Write the feedback file
            feedback = SeedsBatchFeedback(
                new_coverage = bool(new_seeds),
                should_cancel_script = result.was_aborted,
            )

            if self.verbose:
                logger.info(f'{batch}: writing feedback {feedback}')

            feedback.save_to_file(self.feedback_output_dir / (batch.path.name + '.json'))

        if self.verbose:
            logger.info(f'{batch}: done: result is {result}')

        if new_seeds:
            self.new_seeds_callback(batch.harness, new_seeds)

        # Split the result into seeds that *crashed* (to submit to
        # VAPI), seeds that *exited* (which we can just discard), and
        # seeds that *timed out* (to be re-tested with a longer timeout
        # later)
        timeouts_result, exits_result, other_crashes_result = result.split_by_timeouts_exits_and_other()
        del result

        # Send the crash and timeout seeds where they belong
        if batch.harness.scorable_timeout_duration is not None:
            for failure in timeouts_result.failures:
                if self.verbose:
                    logger.info(f'Registering a slow seed: {failure}')
                self.slow_seeds_queue.put(SlowSeed(failure.input_path, batch.harness))

        self.send_to_submission_worker(batch.harness, other_crashes_result.failures)

    def process_slow_seed(
        self,
        env: AbstractLibfuzzerEnvironment,
        seed: SlowSeed,
    ):
        """
        Re-test a single seed that was slow during a merge step, and if
        it seems to be scorable as a timeout, submit it
        """
        if self.verbose:
            logger.info(f'Processing slow seed: {seed}')

        if seed.harness.scorable_timeout_duration is None:
            return

        long_timeout = seed.harness.scorable_timeout_duration * TIMEOUT_BUFFER_FACTOR

        invoc = env.prepare_invocation(
            seed.harness.path_in_out_dir,
            [],
            [seed.path.parent],
            overall_timeout=long_timeout,
            per_seed_timeout=long_timeout,
        )

        invoc.mounts.artifact_prefix_host.mkdir(exist_ok=True)

        result = invoc.run_single_exec(seed.path)

        if self.verbose:
            logger.info(f'{seed}: done: result is {result}')

        shutil.rmtree(invoc.mounts.artifact_prefix_host)

        DEFAULT_SUMMARY = b'(timed out)'

        # Note: we have no way of knowing from this test whether this
        # seed would introduce any new coverage. But frankly, we
        # probably don't want to send it to the fuzzers even if it
        # would. It takes over a second to execute, after all.

        delete_seed = True

        if result.was_aborted or result.execution_time >= long_timeout - 0.1:
            # It got timed out by subprocess, and as a result, we may
            # not actually have a LibfuzzerFailure object to submit.
            # (And even if we do, it might show some type of crash other
            # than a timeout, so we shouldn't really trust whatever it
            # says.)

            # So we should synthesize our own LibfuzzerFailure object.

            failure = LibfuzzerFailure(seed.path, None, Sanitizer.TIMEOUT, DEFAULT_SUMMARY)

            self.send_to_submission_worker(seed.harness, [failure])
            delete_seed = False

        elif result.failure is not None and result.failure.is_timeout():
            # It timed out due to libfuzzer's own internal timeout.

            # Just in case: make sure it has a non-None summary, since
            # the submission worker discards crashes that don't have
            # summaries.
            if result.failure.summary is None:
                result.failure.summary = DEFAULT_SUMMARY

            self.send_to_submission_worker(seed.harness, [result.failure])
            delete_seed = False

        else:
            # Either it crashed for some other reason, or it finished
            # cleanly with the extended timeout. Either way, sending a
            # seed this slow to the fuzzers would be kind of poisonous,
            # so let's just get rid of it (leave delete_seed as True)
            pass

        if delete_seed:
            # We reach here if the seed didn't get sent to the
            # submission worker. The submission worker deletes any seed
            # sent to it once it's done with it, but otherwise, we have
            # to do it ourselves here.
            seed.path.unlink(missing_ok=True)


class SubmissionWorker(Process):
    """
    A specific process/thread dedicated to submitting crashes to VAPI.
    This exists so that we can have exactly one VapiSubmitter instance
    for the whole application, allowing it to do crash deduplication.
    """
    queue: Queue
    submitter: VapiSubmitter

    def __init__(self, queue: Queue, **kwargs):
        super().__init__(**kwargs)
        self.queue = queue
        self.submitter = VapiSubmitter()

    def run(self) -> None:
        """Main entrypoint for the thread/process"""
        while True:
            try:
                harness, failures = self.queue.get()

                for failure in failures:
                    if failure.input_path is None:
                        # (shouldn't happen)
                        logger.warning(
                            f'Skipping submitting potential crash for {harness.cp_name} / {harness.name}'
                            " because it doesn't have a path"
                        )
                    elif failure.input_path.stat().st_size == 0:
                        logger.warning(
                            f'Skipping submitting potential crash for {harness.cp_name} / {harness.name}'
                            " because it has length 0"
                        )
                    elif failure.summary is None:
                        logger.warning(
                            f'Skipping submitting potential crash for {harness.cp_name} / {harness.name}'
                            " because it doesn't have a summary"
                        )
                    else:
                        self.submitter.submit_crash(
                            harness.cp_name,
                            harness.name,
                            failure.input_path,
                            failure.summary,
                            is_timeout=failure.is_timeout(),
                        )

                    # Also delete the seed
                    if failure.input_path is not None:
                        failure.input_path.unlink(missing_ok=True)

            except Exception:
                logger.error(traceback.format_exc())


class LibfuzzerPool:
    """
    Class representing the pool of processes/threads managing
    libfuzzer-merge environments
    """
    config: Configuration
    workers: list[Worker]
    submission_worker: SubmissionWorker | None
    input_queues: list[Queue]
    submit_queue: Queue | None
    slow_seeds_queue: Queue

    def __init__(self, config: Configuration, new_seeds_callback: NewSeedsCallback):
        super().__init__()

        self.config = config
        self.workers = []
        self.input_queues = []
        self.slow_seeds_queue = Queue()

        # If this already exists, we should keep it, since the fuzzers
        # already have these seeds and their coverage, and we don't want
        # to waste time slowly "rediscovering" it
        coverage_seeds_dir = config.temp_dir / 'coverage_seeds'
        coverage_seeds_dir.mkdir(exist_ok=True, parents=True)

        if is_vapi_enabled():
            self.submit_queue = Queue()
            self.submission_worker = SubmissionWorker(self.submit_queue)
        else:
            logger.info('Not creating a submission worker, because VAPI is not enabled')
            self.submit_queue = self.submission_worker = None

        for i in range(config.worker_pool_size):
            input_queue: Queue = Queue(WORKER_QUEUE_MAX_SIZE)
            self.input_queues.append(input_queue)

            worker_crashing_seeds_dir = config.temp_dir / f'proc_{i:03d}_crashes'
            worker_temp_dir = config.temp_dir / f'proc_{i:03d}_temp'

            # If the crashing-seeds directory already exists, just
            # delete it. We just use that to ensure that the seed files
            # will have a place to exist long enough for the submission
            # worker to have time to submit them -- so if there's
            # anything in there, it should already be taken care of
            # (unless we crashed during submission, which... maybe we
            # should handle that?)
            shutil.rmtree(worker_crashing_seeds_dir, ignore_errors=True)

            # I'd like to say the same about the worker-temp directory,
            # but we can't just delete that one if it already exists. It
            # has lots of mounts to subdirectories of /, so if we were
            # to delete it without unmounting those, we'd probably just
            # destroy the container we're running in. And unmounting
            # on Linux isn't super reliable, so... let's just make a new
            # directory instead.
            j = 2
            while worker_temp_dir.is_dir():
                worker_temp_dir = config.temp_dir / f'proc_{i:03d}_temp_{j}'
                j += 1

            worker = Worker(
                i,
                input_queue,
                self.submit_queue,
                self.slow_seeds_queue,
                coverage_seeds_dir,
                worker_crashing_seeds_dir,
                worker_temp_dir,
                config.feedback_output_dir,
                config.runner_docker_image,
                new_seeds_callback,
                verbose=config.verbose,
            )
            self.workers.append(worker)

        if self.submission_worker is not None:
            self.submission_worker.start()

        for p in self.workers:
            p.start()

    def add_seeds_batch(self, path: Path, harness: Harness, script_id: int | None, *, needs_feedback: bool) -> None:
        """Submit a directory of seeds to the process pool."""
        batch = SeedsBatch(path, harness, script_id, needs_feedback)

        # Note: I had the idea to make it try different queues at random
        # until it finds the first one it can add to without blocking,
        # but that'd actually lead to degenerate behavior: the workers
        # that are already overworked and not checking their queue very
        # often will be given even more work, and ones that don't have
        # much work and are checking their queue frequently will be
        # given even less. So don't do that. Just keep the distribution
        # uniform.

        random.choice(self.input_queues).put(batch)
