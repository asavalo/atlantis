from crete.commons.crash_analysis.contexts import CrashAnalyzerContext
from crete.framework.code_inspector.contexts import CodeInspectorContext


class FaultLocalizationContext(CrashAnalyzerContext, CodeInspectorContext):
    pass
