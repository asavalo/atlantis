from crete.atoms.detection import Detection
from crete.framework.analyzer.services.call_trace.models import FunctionCall
from crete.framework.analyzer.services.call_trace.parsers.c_cpp import (
    parse_call_trace_log_for_c,
)
from crete.framework.analyzer.services.call_trace.parsers.jvm import (
    parse_call_trace_log_for_jvm,
)
from crete.framework.evaluator.contexts import EvaluatingContext


def get_call_trace(
    context: EvaluatingContext,
    detection: Detection,
    pov_result: tuple[bytes, bytes],
    simple: bool = False,
) -> list[FunctionCall] | None:
    """Parse the call trace log and return a list of FunctionCall objects."""
    call_trace_log_path = context["pool"].out_directory / "call_trace.log"
    if not call_trace_log_path.exists():
        context["logger"].warning("Call trace log not found.")
        return None

    match detection.language:
        case "c" | "c++" | "cpp":
            return parse_call_trace_log_for_c(
                call_trace_log_path.read_text(),
                context["pool"].source_directory,
                simple=simple,
            )
        case "jvm":
            return parse_call_trace_log_for_jvm(
                call_trace_log_path.read_text(),
                context["pool"].source_directory,
                simple=simple,
            )
