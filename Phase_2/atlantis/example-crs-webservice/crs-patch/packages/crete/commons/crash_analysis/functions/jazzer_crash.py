import glob
import re
from pathlib import Path
from typing import Callable

from crete.commons.crash_analysis.models import CrashAnalysisResult
from crete.commons.crash_analysis.types import Frame, FunctionFrame, InvalidFrame
from crete.framework.environment.functions import resolve_project_path

from .common import analyze_crash

_jazzer_frame_regex = re.compile(rb"^\s*at (?:(.+)\.)?(.+)\.(.+)\((.+\.java):(\d+)\)$")


def analyze_jazzer_crash(source_directory: Path, output: bytes) -> CrashAnalysisResult:
    path_map = _create_path_map(source_directory)

    return analyze_crash(
        source_directory=source_directory,
        output_preprocessing_function=jazzer_output_preprocess,
        line_to_frame_function=_jazzer_line_to_frame(path_map),
        find_sanitizer_index_function=_jazzer_find_sanitizer_index,
        output=output,
    )


def _create_path_map(source_directory: Path) -> list[Path]:
    return list(
        map(
            lambda file: Path(file),
            glob.glob("**/*.java", root_dir=source_directory, recursive=True),
        )
    )


def jazzer_output_preprocess(output: bytes) -> list[bytes]:
    if b"== Java Exception:" in output:
        output = output[output.index(b"== Java Exception:") :]
    if b"== ERROR: libFuzzer:" in output:
        output = output[output.index(b"== ERROR: libFuzzer:") :]
    return [output]


def _jazzer_line_to_frame(
    path_map: list[Path],
) -> Callable[[bytes, int, Path], Frame | None]:
    def _(
        line: bytes,
        line_number_in_log: int,
        source_directory: Path,
    ) -> Frame | None:
        return _jazzer_line_to_frame_with_path_map(
            line, line_number_in_log, source_directory, path_map
        )

    return _


def _jazzer_line_to_frame_with_path_map(
    line: bytes,
    line_number_in_log: int,
    source_directory: Path,
    path_map: list[Path],
) -> Frame | None:
    matched = _jazzer_frame_regex.match(line)
    if matched is None:
        return None

    """
    at com.aixcc.activemq.harnesses.one.ActivemqOne.fuzzerTestOneInput(ActivemqOne.java:38)
    matched.group(1): com.aixcc.activemq.harnesses.one
    matched.group(2): ActivemqOne
    matched.group(3): fuzzerTestOneInput
    matched.group(4): ActivemqOne.java
    matched.group(5): 38
    """
    package_name = matched.group(1).decode() if matched.group(1) else ""
    _class_name = matched.group(2).decode()
    method_name = matched.group(3).decode()
    file_name = matched.group(4).decode()
    line_number = int(matched.group(5).decode()) - 1

    # file_path = com/aixcc/activemq/harnesses/one/ActivemqOne.java
    file_path = Path(*package_name.split(".")) / file_name

    resolved_path_candidates = list(
        filter(
            lambda f: str(f).endswith(str(file_path)),
            path_map,
        )
    )

    if len(resolved_path_candidates) > 0:
        resolved_path = resolve_project_path(
            resolved_path_candidates[0], source_directory
        )
        if resolved_path is not None:
            return FunctionFrame(
                method_name, resolved_path, line_number, line_number_in_log
            )

    return InvalidFrame()


def _jazzer_find_sanitizer_index(frames: list[FunctionFrame]) -> int:
    # Default to the last frame
    return 0
