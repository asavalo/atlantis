import re
from typing import Callable, cast

from crete.atoms.detection import Detection
from crete.framework.environment.exceptions import ChallengePoVFoundError
from crete.framework.evaluator.contexts import EvaluatingContext


class ValgrindAnalyzer:
    """
        A runner that executes a PoV with valgrind.

    Methods:
        - analyze: re-builds the given CP without sanitizer flags, executes a PoV with valgrind, returning a valgrind report (`str`) for the given PoV execution.
    """

    def __init__(self):
        pass

    def analyze(
        self,
        context: EvaluatingContext,
        detection: Detection,
    ) -> str | None:
        # self._analyze(context, detection)
        return cast(
            Callable[..., str | None],
            context["memory"].cache(self._analyze, ignore=["context"]),  # pyright: ignore[reportUnknownMemberType]
        )(context, detection)

    def _analyze(
        self,
        context: EvaluatingContext,
        detection: Detection,
    ) -> str | None:
        # Valgrind requires the sanitizers not to be enabled.
        # So, build our CP without sanitizer-related flags first.
        #   * For more details, see https://github.com/google/sanitizers/issues/810
        environment = context["pool"].use(context, "VALGRIND")

        if (environment is None) or (len(detection.blobs) == 0):
            return None

        try:
            stdout, _ = environment.run_pov(context, detection)  # type: ignore
        except ChallengePoVFoundError as e:
            stdout = e.stdout.decode(errors="replace")

        return _extract_valgrind_report(stdout)  # type: ignore


def _extract_valgrind_report(input_txt: str) -> str | None:
    """
    Valgrind's report starts with "==??==", where ?? indicates a certain number (e.g., "==14==").
    This function gathers such lines and creates a clean valgrind report without other unintended texts.
    """
    pattern = r"^==\d+==.*"
    matching_lines = [line for line in input_txt.split("\n") if re.match(pattern, line)]

    if len(matching_lines) == 0:
        return None

    return "\n".join(matching_lines)
