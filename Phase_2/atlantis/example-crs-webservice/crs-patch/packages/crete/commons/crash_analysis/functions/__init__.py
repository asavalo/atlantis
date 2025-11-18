import re

from crete.atoms.detection import Detection
from crete.commons.crash_analysis.contexts import CrashAnalyzerContext
from crete.commons.crash_analysis.models import CrashAnalysisResult
from crete.commons.crash_analysis.patterns import BUG_CLASS_PATTERNS
from crete.commons.crash_analysis.types import CrashAnalyzer, CrashStacks
from crete.framework.sarif_parser.services.default import DefaultSarifParser

from .jazzer_crash import analyze_jazzer_crash
from .userland_crash import analyze_userland_crash

__all__ = ["get_crash_stacks"]


def get_crash_stacks(
    context: CrashAnalyzerContext, detection: Detection
) -> CrashStacks | None:
    if crash_analysis_result := get_crash_analysis_results(context, detection):
        return crash_analysis_result.crash_stacks
    else:
        return None


def get_crash_analysis_results(
    context: CrashAnalyzerContext, detection: Detection
) -> CrashAnalysisResult | None:
    if (
        pov_output := context["crash_log_analyzer"].analyze(context, detection)
    ) is None:
        return None

    crash_analyzer = _get_crash_analyzer(detection)
    crash_analysis_results = crash_analyzer(
        context["pool"].source_directory, pov_output
    )

    # If the crash analyzer returns an empty crash stack, it means that our analysis
    # is somehow wrong.
    if len(crash_analysis_results.crash_stacks) == 0:
        context["logger"].warning(
            "Crash analysis results is empty. This should not happen."
        )
        return None

    return crash_analysis_results


def get_bug_class(context: CrashAnalyzerContext, detection: Detection) -> str | None:
    if crash_log := context["crash_log_analyzer"].analyze(context, detection):
        return extract_bug_class(crash_log.decode(errors="replace"))
    elif sarif_report := detection.sarif_report:
        return DefaultSarifParser().get_detected_rule(sarif_report)
    else:
        return None


def extract_bug_class(crash_log: str) -> str | None:
    for pattern in BUG_CLASS_PATTERNS:
        match = re.search(pattern, crash_log)
        if match:
            return match.group(1)
    return None


def _get_crash_analyzer(detection: Detection) -> CrashAnalyzer:
    match detection.language:
        case "c" | "cpp" | "c++":
            return analyze_userland_crash
        case "jvm":
            return analyze_jazzer_crash
