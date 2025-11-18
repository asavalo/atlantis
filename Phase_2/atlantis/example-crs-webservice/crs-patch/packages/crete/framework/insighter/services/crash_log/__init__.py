from python_aixcc_challenge.language.types import Language

from crete.atoms.detection import Detection
from crete.commons.crash_analysis.functions.jazzer_crash import jazzer_output_preprocess
from crete.commons.crash_analysis.functions.userland_crash import (
    userland_output_preprocess,
)
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol


class CrashLogInsighter(InsighterProtocol):
    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        if (
            pov_output := context["crash_log_analyzer"].analyze(context, detection)
        ) is None:
            context["logger"].warning("Failed to run PoV")
            return None

        return _crop_sanitizer_log(context, pov_output, detection.language).decode(
            errors="replace"
        )


def _crop_sanitizer_log(
    context: InsighterContext, log: bytes, language: Language
) -> bytes:
    match language:
        case "c" | "c++" | "cpp":
            blocks = userland_output_preprocess(log)
        case "jvm":
            blocks = jazzer_output_preprocess(log)

    if len(blocks) == 0:
        # It might be possible that the log does not contain any sanitizer output.
        # In this case, we return the original log.
        context["logger"].warning("Failed to crop sanitizer log")
        return log

    return b"\n".join(blocks)
