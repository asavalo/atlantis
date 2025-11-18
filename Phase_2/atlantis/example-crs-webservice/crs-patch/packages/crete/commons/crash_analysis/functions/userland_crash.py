import re
from pathlib import Path

from crete.commons.crash_analysis.models import (
    CrashAnalysisResult,
    FunctionFrame,
    InvalidFrame,
)
from crete.commons.crash_analysis.types import Frame
from crete.framework.environment.functions import resolve_project_path

from .common import analyze_crash

_asan_frame_regex = re.compile(rb"^\s+#\d+ 0x[0-9a-f]+ in (.+) ([^:]+):(\d+)(?::\d+)?$")
_asan_weak_frame_regex = re.compile(rb"^\s+#\d+ 0x[0-9a-f]+ in (.+)$")
_ubsan_frame_regex = re.compile(rb"^\s+#\d+ 0x[0-9a-f]+ in (.+)$")


def analyze_userland_crash(
    source_directory: Path, output: bytes
) -> CrashAnalysisResult:
    return analyze_crash(
        source_directory=source_directory,
        output_preprocessing_function=userland_output_preprocess,
        line_to_frame_function=_userland_line_to_frame,
        find_sanitizer_index_function=_userland_find_sanitizer_index,
        output=output,
    )


def _find_by_regex(output: bytes, pattern: bytes, start: int) -> tuple[int, int] | None:
    match = re.search(pattern, output[start:])
    if match is None:
        return None

    return match.start(0), match.end(0) - match.start(0)


def userland_output_preprocess(output: bytes) -> list[bytes]:
    segments: list[int] = []
    current_position = 0

    while True:
        matches = [
            _find_by_regex(output, pattern, current_position)
            for pattern in [
                rb"([^\n:]+:\d+:\d+: runtime error: )",
                b"==ERROR: UndefinedBehaviorSanitizer:",
                b"==ERROR: AddressSanitizer:",
                b"== ERROR: libFuzzer:",
                b"==WARNING: MemorySanitizer:",
                b"==ERROR: MemorySanitizer:",
                b"==ERROR: LeakSanitizer:",
            ]
        ]

        if all(match is None for match in matches):
            segments.append(len(output))
            break

        start, length = min(
            [match for match in matches if match is not None],
        )

        assert length > 0, "Length of the match should be greater than 0"

        segments.append(current_position + start)
        current_position += start + length

    return [output[start:end] for start, end in zip(segments, segments[1:])]


def _userland_line_to_frame(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
) -> Frame | None:
    return _line_to_asan_frame(
        line, line_number_in_log, source_directory
    ) or _line_to_ubsan_frame(line, line_number_in_log, source_directory)


def _line_to_asan_frame(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
) -> Frame | None:
    match = _asan_weak_frame_regex.match(line)
    if match is None:
        return None

    match = _asan_frame_regex.match(line)
    if match is None:
        return InvalidFrame()

    function_name = match.group(1).decode()
    file = resolve_project_path(Path(match.group(2).decode()), source_directory)
    line_number = int(match.group(3)) - 1

    if file is None:
        return InvalidFrame()

    return FunctionFrame(
        function_name=function_name,
        file=file,
        line=line_number,
        line_number_in_log=line_number_in_log,
    )


def _line_to_ubsan_frame(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
) -> Frame | None:
    match = _ubsan_frame_regex.match(line)
    if match is None:
        return None

    match = _ubsan_frame_regex.match(line)
    if match is None:
        return InvalidFrame()

    function_name = match.group(1).decode()
    file = resolve_project_path(Path(match.group(2).decode()), source_directory)
    line_number = int(match.group(3)) - 1

    if file is None:
        return InvalidFrame()

    return FunctionFrame(
        function_name=function_name,
        file=file,
        line=line_number,
        line_number_in_log=line_number_in_log,
    )


def _userland_find_sanitizer_index(frames: list[FunctionFrame]) -> int:
    # Default to the last frame
    return 0
