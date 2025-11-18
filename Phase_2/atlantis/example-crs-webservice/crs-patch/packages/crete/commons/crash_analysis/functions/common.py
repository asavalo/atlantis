from pathlib import Path
from typing import Callable

from crete.commons.crash_analysis.models import (
    CrashAnalysisResult,
    CrashStack,
    FunctionFrame,
    InvalidFrame,
)
from crete.commons.crash_analysis.types import CrashStacks, Frame


def _append_crash_stack_if_not_empty(
    crash_stacks: CrashStacks,
    frames: list[FunctionFrame],
    find_sanitizer_index_function: Callable[[list[FunctionFrame]], int],
):
    if len(frames) == 0:
        return

    crash_stacks.append(
        CrashStack(frames=frames, sanitizer_index=find_sanitizer_index_function(frames))
    )


def analyze_crash(
    source_directory: Path,
    output_preprocessing_function: Callable[[bytes], list[bytes]],
    line_to_frame_function: Callable[[bytes, int, Path], Frame | None],
    find_sanitizer_index_function: Callable[[list[FunctionFrame]], int],
    output: bytes,
) -> CrashAnalysisResult:
    blocks = output_preprocessing_function(output)

    crash_stacks: CrashStacks = []
    for block in blocks:
        frames: list[FunctionFrame] = []
        for index, line in enumerate(block.splitlines()):
            frame = line_to_frame_function(line, index, source_directory)

            match frame:
                case FunctionFrame():
                    frames.append(frame)
                case InvalidFrame():
                    pass
                case None:
                    _append_crash_stack_if_not_empty(
                        crash_stacks, frames, find_sanitizer_index_function
                    )
                    frames = []

        # Add the last crash stack
        _append_crash_stack_if_not_empty(
            crash_stacks, frames, find_sanitizer_index_function
        )

    return CrashAnalysisResult(
        output=b"".join(blocks),
        crash_stacks=crash_stacks,
    )
