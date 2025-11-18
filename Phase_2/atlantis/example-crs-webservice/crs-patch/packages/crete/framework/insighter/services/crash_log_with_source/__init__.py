from pathlib import Path

from crete.atoms.detection import Detection
from crete.commons.crash_analysis import get_crash_analysis_results
from crete.commons.crash_analysis.models import CrashStack, FunctionFrame
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol


class CrashLogWithSourceInsighter(InsighterProtocol):
    def __init__(self, depth: int = 5):
        self._depth = depth

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        if (
            crash_analysis_result := get_crash_analysis_results(context, detection)
        ) is None:
            return None

        crash_stacks = crash_analysis_result.crash_stacks
        if len(crash_stacks) == 0:
            context["logger"].warning("No crash stacks found")
            return None

        multi_source_frames = self._find_multi_source_frames(crash_stacks)
        content = ""
        for index, line in enumerate(crash_analysis_result.output.splitlines()):
            content += line.decode("utf-8", errors="replace") + "\n"
            frame = self._get_multi_source_frame(index, multi_source_frames)
            if frame:
                content += self._get_source_code_snippet(
                    frame, 5, context["pool"].source_directory
                )
        return content

    def _find_multi_source_frames(
        self, crash_stacks: list[CrashStack]
    ) -> list[FunctionFrame]:
        """
        Multi source frames are the frames that will be printed with multiple source code lines.
        We will set those frames from top-k frames starting from the sanitizer triggering frame.
        """
        ret: list[FunctionFrame] = []
        for crash_stack in crash_stacks:
            for i, frame in enumerate(crash_stack.frames):
                if (
                    i >= crash_stack.sanitizer_index
                    and i < crash_stack.sanitizer_index + self._depth
                ):
                    ret.append(frame)
        return ret

    def _get_multi_source_frame(
        self, line_number_in_log: int, multi_source_frames: list[FunctionFrame]
    ) -> FunctionFrame | None:
        for frame in multi_source_frames:
            if frame.line_number_in_log == line_number_in_log:
                return frame
        return None

    def _get_source_code_snippet(
        self, frame: FunctionFrame, window_length: int, source_directory: Path
    ) -> str:
        lines = frame.file.read_text(errors="replace").splitlines()
        content = f"\n{frame.file.relative_to(source_directory)}:{frame.line + 1} in {frame.function_name}\n"
        for i, line in enumerate(lines):
            if i > frame.line - window_length and i < frame.line + window_length:
                if i == frame.line:
                    content += f" => {str(i + 1).rjust(5)} | {line}\n"
                else:
                    content += f"{str(i + 1).rjust(9)} | {line}\n"
        return content + "\n"
