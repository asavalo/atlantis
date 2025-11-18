from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class FunctionFrame:
    function_name: str
    file: Path
    line: int
    line_number_in_log: int


@dataclass(frozen=True)
class InvalidFrame:
    function_name: str = "invalid"
    file: Path = Path("")
    line: int = 0
    line_number_in_log: int = 0


@dataclass(frozen=True)
class CrashStack:
    frames: list[FunctionFrame]
    sanitizer_index: int

    def iter_relevant_frames(
        self, depth: int | None = None
    ) -> Iterator[tuple[int, FunctionFrame]]:
        frames = self.frames[self.sanitizer_index :]
        if depth is not None:
            frames = frames[:depth]

        return enumerate(frames, start=self.sanitizer_index)


@dataclass(frozen=True)
class CrashAnalysisResult:
    output: bytes = b""
    crash_stacks: list[CrashStack] = field(default_factory=list)
