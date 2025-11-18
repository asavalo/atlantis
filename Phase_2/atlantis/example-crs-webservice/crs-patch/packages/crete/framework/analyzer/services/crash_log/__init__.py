from crete.atoms.detection import Detection
from crete.framework.environment.functions import get_pov_results
from crete.framework.evaluator.contexts import EvaluatingContext


class CrashLogAnalyzer:
    def _get_pov_results_no_cache(
        self, context: EvaluatingContext, detection: Detection
    ) -> tuple[bytes, bytes] | None:
        environment = context["pool"].use(context, "DEBUG")
        if environment is None:
            environment = context["pool"].restore(context)

        return get_pov_results(environment, context, detection)

    def _get_pov_results(
        self, context: EvaluatingContext, detection: Detection
    ) -> tuple[bytes, bytes] | None:
        return context["memory"].cache(
            self._get_pov_results_no_cache, ignore=["context"]
        )(context, detection)

    def analyze(self, context: EvaluatingContext, detection: Detection) -> bytes | None:
        if results := self._get_pov_results(context, detection):
            return results[0] + results[1]
        else:
            return None
