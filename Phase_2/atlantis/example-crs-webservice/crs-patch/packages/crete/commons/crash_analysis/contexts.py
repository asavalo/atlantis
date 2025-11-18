from crete.framework.analyzer.services.call_trace import CallTraceAnalyzer
from crete.framework.analyzer.services.crash_log import CrashLogAnalyzer
from crete.framework.evaluator.contexts import EvaluatingContext


class CrashAnalyzerContext(EvaluatingContext):
    crash_log_analyzer: CrashLogAnalyzer
    call_trace_snapshot: CallTraceAnalyzer
