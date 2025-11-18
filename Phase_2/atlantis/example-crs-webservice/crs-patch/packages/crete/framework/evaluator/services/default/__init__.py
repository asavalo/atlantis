from crete.atoms.action import (
    Action,
    CompilableDiffAction,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
    WrongDiffAction,
)
from crete.atoms.detection import Detection
from crete.commons.logging.context_managers import logging_performance
from crete.framework.agent.functions import store_debug_file
from crete.framework.environment.exceptions import (
    ChallengeBuildFailedError,
    ChallengePoVFoundError,
    ChallengeTestFailedError,
    ChallengeWrongPatchError,
)
from crete.framework.evaluator import EvaluatingContext, EvaluatorProtocol


class DefaultEvaluator(EvaluatorProtocol):
    def evaluate(
        self,
        context: EvaluatingContext,
        diff: bytes,
        detection: Detection,
    ) -> Action:
        action = self._evaluate_internal(context, diff, detection)
        context["pool"].restore(context)
        return action

    def _evaluate_internal(
        self,
        context: EvaluatingContext,
        diff: bytes,
        detection: Detection,
    ) -> Action:
        environment = context["pool"].restore(context)

        with logging_performance(context, header="Patching"):
            try:
                environment.patch(context, diff)

            except ChallengeWrongPatchError as e:
                context["logger"].exception("Failed to apply the patch")
                return WrongDiffAction(
                    diff=diff,
                    stdout=e.stdout,
                    stderr=e.stderr,
                )
            except ChallengeBuildFailedError as e:
                context["logger"].error("Failed to build the challenge")
                store_debug_file(
                    context,
                    "build_failed_stdout.txt",
                    e.stdout.decode(errors="replace"),
                )
                store_debug_file(
                    context,
                    "build_failed_stderr.txt",
                    e.stderr.decode(errors="replace"),
                )

                return UncompilableDiffAction(
                    diff=diff,
                    stdout=e.stdout,
                    stderr=e.stderr,
                )
            except Exception as e:
                context["logger"].exception("Unknown error occurred")

                return UnknownErrorAction(error=e)

        with logging_performance(context, header="Checking build"):
            try:
                environment.check_build(context)
            except ChallengeBuildFailedError as e:
                context["logger"].error("Failed to build the challenge")
                store_debug_file(
                    context,
                    "build_failed_stdout.txt",
                    e.stdout.decode(errors="replace"),
                )
                return CompilableDiffAction(
                    diff=diff,
                    stdout=e.stdout,
                    stderr=e.stderr,
                )
            except Exception as e:
                context["logger"].exception("Unknown error occurred")
                return UnknownErrorAction(error=e)

        with logging_performance(context, header="Running PoV"):
            try:
                if len(detection.blobs) > 0:
                    environment.run_pov(context, detection)
                else:
                    context["logger"].warning("No blob data found for the detection")

            except ChallengePoVFoundError as e:
                context["logger"].error(e)
                context["logger"].exception(e)
                return VulnerableDiffAction(
                    diff=diff,
                    stdout=e.stdout,
                    stderr=e.stderr,
                )

            except Exception as e:
                context["logger"].exception("Unknown error occurred")
                return UnknownErrorAction(error=e)

        with logging_performance(context, header="Testing"):
            try:
                environment.run_tests(context)
            except ChallengeTestFailedError as e:
                context["logger"].exception("Failed to run the tests")

                return CompilableDiffAction(
                    diff=diff,
                    stdout=e.stdout,
                    stderr=e.stderr,
                )
            except Exception as e:
                context["logger"].exception("Unknown error occurred")
                return UnknownErrorAction(error=e)

        return SoundDiffAction(diff=diff)
