from crete.atoms.detection import Detection
from crete.framework.analyzer.services.call_trace.models import FunctionCall
from crete.framework.analyzer.services.call_trace.parsers import get_call_trace
from crete.framework.environment.functions import get_pov_results
from crete.framework.evaluator.contexts import EvaluatingContext


class CallTraceAnalyzer:
    # TODO: Enable joblib cache
    def analyze(
        self, context: EvaluatingContext, detection: Detection, simple: bool = False
    ) -> list[FunctionCall] | None:
        """Build with LLVM pass and run the PoV to capture the call trace."""
        if len(detection.blobs) == 0:
            return None

        environment = context["pool"].use(context, "CALL_TRACE")
        if environment is None:
            context["logger"].warning("Call trace environment not found.")
            return None

        if results := get_pov_results(environment, context, detection):
            return get_call_trace(context, detection, results, simple=simple)
        else:
            context["logger"].warning("No crash detected with call tracing.")
            return None
