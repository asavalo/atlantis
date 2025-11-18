from crete.atoms.detection import Detection
from crete.framework.analyzer.services.jvm_stackoverflow_stacktrace import (
    JVMStackOverflowStacktraceAnalyzer,
)
from crete.framework.agent.contexts import AgentContext


def get_jvm_stackoverflow_stacktrace(
    context: AgentContext, detection: Detection
) -> str | None:
    overflow_stack = JVMStackOverflowStacktraceAnalyzer().analyze(context, detection)

    if overflow_stack is None:
        return None

    return "FuzzerSecurityIssueLow: Stack overflow\n" + overflow_stack
