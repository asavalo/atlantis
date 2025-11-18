from pathlib import Path
from typing import Literal

from pydantic import BaseModel, TypeAdapter

from crete.commons.interaction.exceptions import TimeoutExpired
from crete.commons.logging.context_managers import logging_performance
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.functions import store_debug_file
from crete.framework.context_builder.protocols import ContextBuilderProtocol
from crete.framework.environment.exceptions import ChallengeTestFailedError

from .action import (
    Action,
    CompilableDiffAction,
    HeadAction,
    NoPatchAction,
    SoundDiffAction,
    UncompilableDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
    WrongDiffAction,
)


class BaseResult(BaseModel):
    project_name: str
    vulnerability_identifier: str
    source_directory: Path


class NoPatchResult(BaseResult):
    variant: Literal["no_patch"]


class DiffResult(BaseResult):
    variant: Literal[
        "sound",
        "vulnerable",
        "compilable",
        "uncompilable",
        "wrong",
        "internal_tests_failure",
    ]
    diff: str
    stdout: bytes
    stderr: bytes


class ErrorResult(BaseResult):
    variant: Literal["unknown_error"]
    error: str


# TODO(v4): rename better
CreteResult = NoPatchResult | DiffResult | ErrorResult
CreteResultModel = TypeAdapter[DiffResult | ErrorResult](CreteResult)


def result_from_action(
    context_builder: ContextBuilderProtocol, action: Action
) -> CreteResult:
    context, detection = context_builder.build(
        previous_action=HeadAction(),
        reflection=None,
    )

    base_result = BaseResult(
        project_name=detection.project_name,
        vulnerability_identifier=detection.vulnerability_identifier,
        source_directory=context["pool"].source_directory,
    )

    match action:
        case HeadAction():
            raise ValueError("HeadAction should not be converted to a report.")
        case SoundDiffAction(diff=diff):
            is_sound = _run_internal_tests_if_exists(context, diff)
            return DiffResult.model_validate(
                {
                    **base_result.model_dump(),
                    "variant": "sound" if is_sound else "internal_tests_failure",
                    "diff": diff,
                    "stdout": "",
                    "stderr": "",
                }
            )
        case (
            CompilableDiffAction(
                diff=diff, stdout=stdout, stderr=stderr, variant=variant
            )
            | VulnerableDiffAction(
                diff=diff, stdout=stdout, stderr=stderr, variant=variant
            )
            | UncompilableDiffAction(
                diff=diff, stdout=stdout, stderr=stderr, variant=variant
            )
            | WrongDiffAction(diff=diff, stdout=stdout, stderr=stderr, variant=variant)
        ):
            return DiffResult.model_validate(
                {
                    **base_result.model_dump(),
                    "variant": variant,
                    "diff": diff,
                    "stdout": stdout,
                    "stderr": stderr,
                }
            )
        case NoPatchAction():
            return NoPatchResult.model_validate(
                {
                    **base_result.model_dump(),
                    "variant": "no_patch",
                }
            )
        case UnknownErrorAction(error=error, variant=variant):
            return ErrorResult.model_validate(
                {
                    **base_result.model_dump(),
                    "variant": "unknown_error",
                    "error": str(error),
                }
            )


def _run_internal_tests_if_exists(context: AgentContext, diff: bytes) -> bool:
    if not context["pool"].internal_test_exists():
        return True

    environment = context["pool"].restore(context)
    try:
        environment.patch(context, diff)
        with logging_performance(context, header="Internal tests"):
            _, _ = environment.run_tests(context)
        context["logger"].debug("Internal tests SUCCESS")
        return True
    except ChallengeTestFailedError as e:
        context["logger"].debug("Internal tests FAILED")
        store_debug_file(
            context, "internal_tests_stdout.txt", e.stdout.decode(errors="replace")
        )
        store_debug_file(
            context, "internal_tests_stderr.txt", e.stderr.decode(errors="replace")
        )
        return False
    except TimeoutExpired:
        context["logger"].debug("Internal tests TIMEOUT")
        return False


# TODO(v4): rename to save_result
def store_result(
    result: CreteResult,
    output_directory: Path,
):
    match result:
        case NoPatchResult(variant=variant):
            (output_directory / f"final-{variant}.empty").touch()
        case DiffResult(variant=variant, diff=diff):
            (output_directory / f"final-{variant}.diff").write_text(diff)
        case ErrorResult(variant=variant, error=error):
            (output_directory / f"final-{variant}.error").write_text(error)
