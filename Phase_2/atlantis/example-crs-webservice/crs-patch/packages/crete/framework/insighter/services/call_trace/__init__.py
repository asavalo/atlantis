from crete.atoms.detection import Detection
from crete.framework.analyzer.services.call_trace import CallTraceAnalyzer
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol


class CallTraceInsighter(InsighterProtocol):
    def __init__(self, depth: int) -> None:
        self._depth = depth

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        call_trace = CallTraceAnalyzer().analyze(context, detection)

        if call_trace is None or len(call_trace) == 0:
            context["logger"].warning("No call trace found")
            return None

        recent_call_trace = call_trace[-self._depth :]

        # According to CodeRover-S paper,
        # "The functions invoked closer to the crash location are presented earlier in this list"
        insight = "other functions executed by the bug-triggering input:\n\n"
        for function_call in reversed(recent_call_trace):
            insight += "  %s (called by %s in %s:%d)\n" % (
                function_call.callee_name,
                function_call.caller_name,
                function_call.caller_file,
                function_call.call_line + 1,
            )

        return insight
