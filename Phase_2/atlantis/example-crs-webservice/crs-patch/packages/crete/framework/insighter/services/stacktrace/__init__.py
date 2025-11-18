from pathlib import Path

from crete.atoms.detection import Detection
from crete.commons.crash_analysis import get_crash_stacks
from crete.commons.crash_analysis.models import CrashStack, FunctionFrame
from crete.commons.utils import add_line_numbers
from crete.framework.analyzer.services.debugger.functions import dump_runtime_values
from crete.framework.analyzer.services.debugger.models import RuntimeValue
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol


class StacktraceInsighter(InsighterProtocol):
    def __init__(self, depth: int = 5, annotate_runtime_value: bool = False):
        self._depth = depth
        self._annotate_runtime_value = annotate_runtime_value

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        if (crash_stacks := get_crash_stacks(context, detection)) is None:
            context["logger"].warning("No crash stacks found")
            return None

        # TODO: For now, we'll use the first crash stack
        # We should consider other stacks depending on the bug class
        # E.g., UAF, Double Free, etc.
        crash_stack = crash_stacks[0]

        runtime_values = self._get_runtime_values(context, detection)
        context["logger"].debug(f"Runtime values: {runtime_values}")

        return self._generate_insight(context, crash_stack, runtime_values)

    def _generate_insight(
        self,
        context: InsighterContext,
        crash_stack: CrashStack,
        runtime_values: list[dict[str, RuntimeValue]] | None,
    ) -> str:
        content = ""
        for i, frame in crash_stack.iter_relevant_frames(depth=self._depth):
            content += _generate_frame_information(
                frame, context["pool"].source_directory
            )

            if runtime_values is not None:
                content += _generate_runtime_value_information(runtime_values[i])

            content += "\n"

        return content

    def _get_runtime_values(
        self, context: InsighterContext, detection: Detection
    ) -> list[dict[str, RuntimeValue]] | None:
        if not self._annotate_runtime_value:
            return None

        match detection.language:
            case "c" | "c++" | "cpp":
                return dump_runtime_values(context, detection, self._depth)
            case "jvm":
                context["logger"].warning(
                    f"{detection.language} is not supported for runtime value annotation"
                )
                return None


def _generate_frame_information(
    frame: FunctionFrame, source_directory: Path, width: int = 10
) -> str:
    template = """
Function: {function_name}
File: {file}
Preceding lines:
{preceding}
Line:
{call_line}
Following lines:
{following}
""".lstrip()

    lines = frame.file.read_text(errors="replace").splitlines()

    preceding = add_line_numbers(
        "\n".join(lines[frame.line - width : frame.line]), frame.line - width + 1
    )

    call_line = add_line_numbers(lines[frame.line], frame.line + 1)

    following = add_line_numbers(
        "\n".join(lines[frame.line + 1 : frame.line + width + 1]), frame.line + 2
    )

    return template.format(
        function_name=frame.function_name,
        file=frame.file.relative_to(source_directory.resolve()),
        preceding=preceding,
        call_line=call_line,
        following=following,
    )


def _generate_runtime_value_information(runtime_values: dict[str, RuntimeValue]) -> str:
    """
    Generate the insight content for runtime values.

    Args:
        runtime_values: runtime value and type of variables
            key: variable name
            value: RuntimeValue (value, type)
    """
    if len(runtime_values) == 0:
        return ""

    content = "Runtime values in the call line:\n"

    for variable, runtime_info in runtime_values.items():
        content += f"  - {variable}:\n"
        assert runtime_info.value is not None or runtime_info.type is not None
        if runtime_info.value is not None:
            content += f"    - Value: {runtime_info.value}\n"
        if runtime_info.type is not None and len(runtime_info.type.split()) < 10:
            content += f"    - Type: {runtime_info.type}\n"

    return content
