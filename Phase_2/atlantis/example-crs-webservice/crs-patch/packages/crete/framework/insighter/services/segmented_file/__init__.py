from pathlib import Path

from crete.atoms.detection import Detection
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.functions import make_relative_to_source_directory
from crete.framework.insighter.protocols import InsighterProtocol


class SegmentedFileInsighter(InsighterProtocol):
    def __init__(self, file: Path, segments: list[tuple[int, int]]):
        self._file = file
        self._segments = _merge_segments(segments)

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        """Example output:

        ### File: file1.py

        ...
        10| def my_function():
        11|     return 0
        12|
        ...
        """

        insight = (
            f"### File: {make_relative_to_source_directory(context, self._file)}\n\n"
        )
        lines = self._file.read_text(errors="replace").splitlines()

        for start, end in self._segments:
            if start != 0:
                insight += "...\n"

            for i in range(start, end):
                insight += f"{i}| {lines[i]}\n"

            if end < len(lines):
                insight += "...\n"

        return insight


def _merge_segments(segments: list[tuple[int, int]]) -> list[tuple[int, int]]:
    segments.sort(key=lambda x: x[0])
    merged_segments: list[tuple[int, int]] = []
    for start, end in segments:
        if not merged_segments or merged_segments[-1][1] < start:
            merged_segments.append((start, end))
        else:
            merged_segments[-1] = (
                merged_segments[-1][0],
                max(merged_segments[-1][1], end),
            )

    # Ensure that the segments are disjoint and sorted
    assert all(r1[1] < r2[0] for r1, r2 in zip(merged_segments, merged_segments[1:]))
    return merged_segments
