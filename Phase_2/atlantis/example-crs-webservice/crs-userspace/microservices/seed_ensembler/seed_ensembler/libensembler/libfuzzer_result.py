from __future__ import annotations

from base64 import b64encode
from dataclasses import dataclass
import enum
import os
from pathlib import Path
import sys
from typing import Iterator

from .logger_wrapper import LoggerWrapper

if sys.version_info >= (3, 11):
    from typing import TYPE_CHECKING
    if TYPE_CHECKING:
        from typing import Self


logger = LoggerWrapper.getLogger(__name__)


def iter_bytes_needles(haystack: bytes, needle: bytes) -> Iterator[int]:
    """
    Iterate over occurrences of a byte string in a larger byte string
    """
    idx = -1
    while True:
        idx = haystack.find(needle, idx + 1)
        if idx == -1:
            break
        yield idx


def align_int_lists_by_checkpoints(
    checkpoints: list[int],
    lists: list[list[int]]
) -> list[list[int | None]]:
    """
    "Align" two or more lists of sorted values by inserting Nones at the
    right spots to make their lengths the same, according to a list of
    "checkpoints".

    The lists in `lists` represent sorted lists of integers that SHOULD
    be parallel, but in reality, they may not all be exactly the same
    length. The goal is to "align" them, by inserting Nones at the right
    spots to make their lengths the same.

    A simple algorithm would just append some Nones to one or more of
    the lists, but instead, we make use of the "checkpoints" information
    -- a list of intermediate values at which the lists should be
    aligned -- to insert them into better locations.

    It's easier to explain through an example. Consider the input

        lists = [[2, 7, 20, 33, 36, 50],
                 [3, 6, 22, 26, 35, 37, 52]]
        checkpoints = [5, 10, 30, 45]

    The algorithm first splits the two lists according to the
    "checkpoints":

           |   |       |       |
        [2 | 7 | 20    | 33 36 | 50] <-- lists[0]
        [3 | 6 | 22 26 | 35 37 | 52] <-- lists[1]
           |   |       |       |
           5   10      30      45    <-- checkpoints

    Now we can see the spot where we should add add a None to the first
    list to make them aligned properly. So the output will be these two
    lists:

        [[2, 7, 20, None, 33, 50],
         [3, 6, 22, 26,   35, 52]]

    (Note: putting the None before the "20" instead of after it would
    also be a valid solution, though this algorithm doesn't do that.)
    """

    # Add one final checkpoint at the end, which is larger than all
    # values across all lists (this simplifies the algorithm)
    checkpoints = list(checkpoints)
    max_ = 0
    for L in lists:
        if L:
            max_ = max(max_, max(L))
    checkpoints.append(max_ + 1)

    new_lists: list[list[int | None]] = [[] for _ in range(len(lists))]
    idxs = [0] * len(lists)

    for checkpoint in checkpoints:
        # Add values from each list until we reach the checkpoint
        for i, L in enumerate(lists):
            while idxs[i] < len(L) and L[idxs[i]] < checkpoint:
                new_lists[i].append(L[idxs[i]])
                idxs[i] += 1

        # Add any required Nones to each list
        target_length = max(len(L) for L in new_lists)
        for L in new_lists:
            while len(L) < target_length:
                L.append(None)

        # The lists should be aligned now. Continue to the next
        # checkpoint

    # Before the loop began, we added an extra checkpoint to the end, so
    # we can be 100% sure that we've now covered the entirety of all
    # lists. So we don't need to do anything else to finish up.

    return new_lists


class Sanitizer(enum.Enum):
    ADDRESS = b'AddressSanitizer'
    MEMORY = b'MemorySanitizer'
    UNDEFINED = b'UndefinedBehaviorSanitizer'
    EXITED = b'libFuzzer: fuzz target exited'
    TIMEOUT = b'libFuzzer: timeout'


@dataclass
class LibfuzzerFailure:
    """Represents a test-case crash or timeout"""
    input_path: Path | None
    output_path: Path | None
    sanitizer: Sanitizer | None
    summary: bytes | None

    def is_timeout(self):
        return self.sanitizer is not None and self.sanitizer == Sanitizer.TIMEOUT

    def is_exit(self):
        return self.sanitizer is not None and self.sanitizer == Sanitizer.EXITED

class LibfuzzerResult:
    """Superclass for different types of libfuzzer results"""
    @staticmethod
    def find_crash_sanitizer(
        stderr: bytes,
        start: int | None = None,
        end: int | None = None,
    ) -> Sanitizer | None:
        """
        Find the Sanitizer of the crashing seed in the indicated region
        of stderr data
        """
        # Search for all of the Sanitizer value strings in the stderr
        # region. If more than one matches, abort and return None
        found_so_far = None
        for s in Sanitizer:
            if stderr.find(s.value, start, end) != -1:
                if found_so_far is None:
                    found_so_far = s
                else:
                    # found two matching sanitizers :/
                    return None

        return found_so_far

    @staticmethod
    def find_crash_summary(
        stderr: bytes,
        start: int | None = None,
        end: int | None = None,
    ) -> bytes | None:
        """
        Find the "SUMMARY:" line of the crashing seed in the indicated
        region of stderr data
        """
        # "SUMMARY: AddressSanitizer: SEGV /src/nginx/src/http/ngx_http_parse.c:2171:18 in ngx_http_parse_chunked"
        #           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

        SUMMARY_START = b'\nSUMMARY: '
        SUMMARY_END = b'\n'

        start_of_summary = stderr.rfind(SUMMARY_START, start, end)
        if start_of_summary != -1:
            start_of_summary += len(SUMMARY_START)

            end_of_summary = stderr.find(SUMMARY_END, start_of_summary, end)
            if end_of_summary != -1:
                return stderr[start_of_summary:end_of_summary]

        return None

@dataclass
class LibfuzzerSingleExecResult(LibfuzzerResult):
    """Represents the result/output of a libfuzzer single-seed execution"""
    failure: LibfuzzerFailure | None
    return_code: int | None
    execution_time: float
    was_aborted: bool

    @classmethod
    def from_path_and_stderr(
        cls,
        path: Path,
        stderr: bytes,
        *,
        return_code: int | None = None,
        execution_time: float,
        was_aborted: bool = False,
    ) -> 'Self':
        """Parse results from stderr data"""
        sanitizer = cls.find_crash_sanitizer(stderr)
        summary = cls.find_crash_summary(stderr)

        if sanitizer is not None and summary is not None:
            failure = LibfuzzerFailure(path, None, sanitizer, summary)
        else:
            failure = None

        return cls(failure, return_code, execution_time, was_aborted)


@dataclass
class LibfuzzerMergeResult(LibfuzzerResult):
    """Represents the result/output of a libfuzzer-merge execution"""
    failures: list[LibfuzzerFailure]
    return_code: int | None
    execution_time: float
    was_aborted: bool

    @classmethod
    def from_stderr(
        cls,
        stderr: bytes,
        *,
        return_code: int | None = None,
        execution_time: float,
        was_aborted: bool = False,
    ) -> 'Self':
        """Parse all results from stderr data"""
        failures: list[LibfuzzerFailure] = []

        # Every crash gets a "Test unit written to" line (which we need
        # to get the SHA-1 hash of the seed, to identify it) and a
        # "SUMMARY" line (which we need for deduplication), but,
        # annoyingly, depending on the type of crash, either of them can
        # be printed first.

        # But every crash should still have both. So if we make a list
        # of all such lines, we can match them up. And while we're at
        # it, let's also look for "caused a failure at the previous
        # merge step" lines too -- they aren't always present, but when
        # they are, they can provide huge hints as to the origin of
        # crashes.

        TEST_UNIT_WRITTEN_TO = b'Test unit written to '
        SUMMARY = b'\nSUMMARY: '
        MERGE_OUTER_ATTEMPT = b'\nMERGE-OUTER: attempt '
        MERGE_INNER = b"MERGE-INNER: '"
        FAILURE_AT_PREVIOUS_MERGE_STEP = b"' caused a failure at the previous merge step"

        all_test_unit_starts = list(iter_bytes_needles(stderr, TEST_UNIT_WRITTEN_TO))
        all_summary_starts = list(iter_bytes_needles(stderr, SUMMARY))
        all_merge_outer_attempt_starts = list(iter_bytes_needles(stderr, MERGE_OUTER_ATTEMPT))
        all_prev_merge_step_failures = list(iter_bytes_needles(stderr, FAILURE_AT_PREVIOUS_MERGE_STEP))

        if len(all_test_unit_starts) != len(all_summary_starts):
            # This has never happened in my testing, but if it ever does
            # happen, I'd like to find out about it
            logger.warning('Test unit / summary lines mismatch '
                f'({len(all_test_unit_starts)} vs. {len(all_summary_starts)}): '
                f'{b64encode(stderr).decode("ascii")}')

        # Either way, make SURE the lists are lined up, using this fancy
        # algorithm I came up with (see its docstring for details)
        (
            all_test_unit_starts,
            all_summary_starts,
            all_prev_merge_step_failures,
        ) = align_int_lists_by_checkpoints(
            all_merge_outer_attempt_starts,
            [all_test_unit_starts, all_summary_starts, all_prev_merge_step_failures],
        )

        for test_unit_start, summary_start, prev_merge_step_failure \
                in zip(all_test_unit_starts, all_summary_starts, all_prev_merge_step_failures):
            # If there's a prev merge step failure message, it actually
            # applies to the PREVIOUS failure, not the current one. So
            # parse its path out and add it to that failure
            input_path = None
            if prev_merge_step_failure is not None:
                merge_inner_start = stderr.rfind(MERGE_INNER, 0, prev_merge_step_failure)
                if merge_inner_start != -1:
                    # print(merge_inner_start, prev_merge_step_failure)
                    # print(stderr[merge_inner_start - 20 : merge_inner_start + 20])
                    # print(stderr[prev_merge_step_failure - 20 : prev_merge_step_failure + 20])
                    # print('--')
                    input_path = stderr[merge_inner_start + len(MERGE_INNER) : prev_merge_step_failure]
                    input_path = Path(os.fsdecode(input_path))

            if input_path is not None and failures:
                failures[-1].input_path = input_path

            # Get the output path from the test-unit line, if possible
            output_path = None
            if test_unit_start is not None:
                output_path_end = stderr.find(b'\n', test_unit_start + len(TEST_UNIT_WRITTEN_TO))
                if output_path_end != -1:
                    output_path = stderr[test_unit_start + len(TEST_UNIT_WRITTEN_TO) : output_path_end]
                    output_path = Path(os.fsdecode(output_path))

            # Get the sanitizer and summary from the summary line, if possible
            sanitizer = summary = None
            if summary_start is not None:
                summary_line_end = stderr.find(b'\n', summary_start + len(SUMMARY))
                if summary_line_end != -1:
                    sanitizer = cls.find_crash_sanitizer(stderr, summary_start, summary_line_end + 1)
                    summary = stderr[summary_start + len(SUMMARY) : summary_line_end]

            if output_path is None:
                # uhh
                continue

            failures.append(LibfuzzerFailure(None, output_path, sanitizer, summary))

        return cls(failures, return_code, execution_time, was_aborted)

    def deduplicate(self) -> None:
        """Delete any duplicate crashes in this result"""
        seen_keys = set()
        new_failures = []

        for failure in self.failures:
            key = (failure.sanitizer, failure.summary)
            if key not in seen_keys:
                seen_keys.add(key)
                new_failures.append(failure)

        self.failures = new_failures

    def split_by_timeouts_exits_and_other(self) -> tuple['Self', 'Self', 'Self']:
        """
        Split this result into three: one containing timeouts, one
        containing exits, and a third containing all other failures.
        """
        timeouts = []
        exits = []
        others = []
        for failure in self.failures:
            if failure.is_timeout():
                timeouts.append(failure)
            elif failure.is_exit():
                exits.append(failure)
            else:
                others.append(failure)

        timeouts_result = LibfuzzerMergeResult(
            timeouts,
            self.return_code,
            self.execution_time,
            self.was_aborted,
        )

        exits_result = LibfuzzerMergeResult(
            exits,
            self.return_code,
            self.execution_time,
            self.was_aborted,
        )

        others_result = LibfuzzerMergeResult(
            others,
            self.return_code,
            self.execution_time,
            self.was_aborted,
        )

        return timeouts_result, exits_result, others_result


def test_list_alignment_algorithm() -> None:
    def test_both(a, b, c, d, e):
        assert align_int_lists_by_checkpoints(a, [b, c]) == [d, e]
        assert align_int_lists_by_checkpoints(a, [c, b]) == [e, d]

    test_both([], [], [], [], [])
    test_both([], [3], [1, 5], [3, None], [1, 5])
    test_both([2], [3], [1, 5], [None, 3], [1, 5])
    test_both([], [1, 2, 3, 4], [], [1, 2, 3, 4], [None, None, None, None])

    test_both(
        [5, 10, 30, 45],
        [2, 7, 20, 33, 36, 50],
        [3, 6, 22, 26, 35, 37, 52],
        [2, 7, 20, None, 33, 36, 50],
        [3, 6, 22, 26,   35, 37, 52],
    )

def test_libfuzzer_output_01(test_data_dir: Path) -> None:
    with (test_data_dir / 'libfuzzer_output_01.txt').open('rb') as f:
        data = f.read()

    result = LibfuzzerMergeResult.from_stderr(data, execution_time=0.0)

    assert len(result.failures) == 15
    assert result.failures[0] == LibfuzzerFailure(
        Path('examples/00a7f52ad8faa266'),
        Path('./crash-356a192b7913b04c54574d18c28d46e6395428ab'),
        Sanitizer.EXITED,
        b'libFuzzer: fuzz target exited',
    )
    assert result.failures[-2] == LibfuzzerFailure(
        Path('examples/0a07e6b152870cb0'),
        Path('./crash-fa35e192121eabf3dabf9f5ea6abdbcbc107ac3b'),
        Sanitizer.EXITED,
        b'libFuzzer: fuzz target exited',
    )
    assert result.failures[-1] == LibfuzzerFailure(
        None,
        Path('./crash-f1abd670358e036c31296e66b3b66c382ac00812'),
        Sanitizer.EXITED,
        b'libFuzzer: fuzz target exited',
    )

def test_libfuzzer_output_02(test_data_dir: Path) -> None:
    with (test_data_dir / 'libfuzzer_output_02.txt').open('rb') as f:
        data = f.read()

    result = LibfuzzerMergeResult.from_stderr(data, execution_time=0.0)

    assert len(result.failures) == 9
    assert result.failures[0] == LibfuzzerFailure(
        Path('examples/0720061be1c789aa'),
        Path('./crash-0716d9708d321ffb6a00818614779e779925365c'),
        Sanitizer.ADDRESS,
        b'AddressSanitizer: SEGV /src/nginx/src/http/ngx_http_parse.c:1277:14 in ngx_http_parse_complex_uri',
    )
    assert result.failures[6] == LibfuzzerFailure(
        Path('examples/03c0a42d2c0ca110'),
        Path('./crash-d435a6cdd786300dff204ee7c2ef942d3e9034e2'),
        Sanitizer.ADDRESS,
        b'AddressSanitizer: SEGV string/../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:342 in __memcpy_evex_unaligned_erms',
    )

def test_libfuzzer_output_03(test_data_dir: Path) -> None:
    with (test_data_dir / 'libfuzzer_output_03.txt').open('rb') as f:
        data = f.read()

    result = LibfuzzerMergeResult.from_stderr(data, execution_time=0.0)

    assert len(result.failures) == 1
    assert result.failures[0] == LibfuzzerFailure(
        Path('dir2/input4.txt'),
        Path('./timeout-1fa7bc717eb4c4d0c7243aa2805059c4d358c8d2'),
        Sanitizer.TIMEOUT,
        b'libFuzzer: timeout',
    )

def test_libfuzzer_output_04(test_data_dir: Path) -> None:
    with (test_data_dir / 'libfuzzer_output_04.txt').open('rb') as f:
        data = f.read()

    result = LibfuzzerMergeResult.from_stderr(data, execution_time=0.0)

    assert len(result.failures) == 1
    assert result.failures[0] == LibfuzzerFailure(
        None,
        Path('./crash-f6e1126cedebf23e1463aee73f9df08783640400'),
        Sanitizer.ADDRESS,
        b'AddressSanitizer: heap-buffer-overflow /src/nginx/src/core/ngx_string.c:1330:14 in ngx_decode_base64_internal',
    )

def run_all_tests():
    test_data_dir = Path(__file__).parent / 'test_data'
    test_list_alignment_algorithm()
    test_libfuzzer_output_01(test_data_dir)
    test_libfuzzer_output_02(test_data_dir)
    test_libfuzzer_output_03(test_data_dir)
    test_libfuzzer_output_04(test_data_dir)
    print('all tests passed')

if __name__ == '__main__':
    run_all_tests()
