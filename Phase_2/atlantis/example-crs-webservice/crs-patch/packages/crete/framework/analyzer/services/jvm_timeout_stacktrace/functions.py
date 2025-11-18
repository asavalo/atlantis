from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.analyzer.services.jvm_timeout_stacktrace import (
    JVMTimeoutStacktraceAnalyzer,
)


def get_jvm_timeout_stacktrace(
    context: AgentContext, detection: Detection
) -> str | None:
    stack_bytes = JVMTimeoutStacktraceAnalyzer().analyze(context, detection)
    if stack_bytes is None:
        return None
    return "ERROR: libFuzzer: timeout\n" + stack_bytes.decode(errors="replace")
