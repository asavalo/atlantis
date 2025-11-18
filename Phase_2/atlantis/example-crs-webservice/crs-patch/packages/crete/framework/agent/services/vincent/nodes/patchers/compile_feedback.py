from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from langgraph.graph import (  # pylint: disable=import-error, no-name-in-module
    END,
)
from python_llm.api.actors import LlmApiManager
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.framework.agent.functions import store_debug_file
from crete.framework.agent.services.vincent.functions import (
    create_prompt,
    extract_requests_in_chat,
    get_last_chat,
    get_token_size,
    send_and_update_llm,
)
from crete.framework.agent.services.vincent.nodes.patchers.globals import (
    DEFAULT_MAXIMUM_FEEDBACK_THRESHOLD,
    FAILSAFE_BUILD_LOG_EXTRACT_LINE_COUNT,
    MAXIMUM_BUILD_LOG_TOKEN_COUNT,
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)

from .patcher import Patcher


class CompileFeedbackPatcher(Patcher):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)

    def __call__(self, state: PatchState) -> dict[str, Any]:
        if state.patch_stage != PatchStage.COMPILE_FEEDBACK:
            raise RuntimeError

        assert state.detection is not None

        if state.feedback_cnt > DEFAULT_MAXIMUM_FEEDBACK_THRESHOLD:
            self.context["logger"].error(
                f"CompileFeedbackPatcher exceeded maximum iteration count: {DEFAULT_MAXIMUM_FEEDBACK_THRESHOLD}"
            )

            state.patch_stage = PatchStage.DONE
            return self._get_dict_from_state(state)

        self.context["pool"].restore(self.context)

        if not self.is_instructed:
            self.context["logger"].info(
                f"******* Compile-feedback Patch Phase (feedback: {state.feedback_cnt}) *******"
            )
            self._instruct_llm_with_guideline(state)
            return self._get_dict_from_state(state)

        assert len(state.requests) == 0

        patch_diff = self._generate_patch_diff(state)

        # New LLM requests can be identified due to fixed responses from the LLM.
        if len(state.requests) != 0:
            return self._get_dict_from_state(state)

        if patch_diff is None:
            state.patch_stage = PatchStage.DONE
            return self._get_dict_from_state(state)

        state.diff = patch_diff

        store_debug_file(
            self.context,
            f"patch-{state.feedback_cnt}.diff",
            state.diff.decode(errors="replace"),
            log_output=False,
        )

        state.action = self.context["evaluator"].evaluate(
            self.context, state.diff, state.detection
        )

        self.context["logger"].info(f"patch result: {state.action.__class__.__name__}")

        return self._finalize_patch(state)

    def _instruct_llm_with_guideline(self, state: PatchState):
        build_log = self._safe_get_build_log(
            state, getattr(state.action, "stdout", b"").decode(errors="replace")
        )

        if build_log is None:
            raise RuntimeError("Build log extraction failed...")

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt(
                "instruct_compile_feedback_patch",
                {
                    "DIFF": state.diff.decode(errors="replace"),
                    "BUILD_LOG": build_log,
                },
            ),
        )

        state.requests = extract_requests_in_chat(get_last_chat(state.messages))
        self.is_instructed = True

    def _safe_get_build_log(self, state: PatchState, full_log: str) -> str | None:
        assert self.detection is not None
        assert len(full_log) != 0

        store_debug_file(
            self.context,
            f"build-error-{state.feedback_cnt}.txt",
            full_log,
            log_output=False,
        )

        token_cnt = get_token_size(full_log)

        if token_cnt < MAXIMUM_BUILD_LOG_TOKEN_COUNT:
            return full_log

        self.context["logger"].info(f"build log token count: {token_cnt}")

        match self.detection.language:
            case "c" | "c++" | "cpp":
                extracted_build_errors = _extract_build_errors_c(full_log)
            case "jvm":
                extracted_build_errors = _extract_build_errors_jvm(full_log)

        if len(extracted_build_errors) == 0:
            self.context["logger"].error(
                f"Failed to extract build errors using grep... Return the last {FAILSAFE_BUILD_LOG_EXTRACT_LINE_COUNT} lines from the build log"
            )
            extracted_build_errors = "".join(
                full_log.splitlines(keepends=True)[
                    -FAILSAFE_BUILD_LOG_EXTRACT_LINE_COUNT:
                ]
            )

        store_debug_file(
            self.context,
            f"extracted-build-error-{state.feedback_cnt}.txt",
            extracted_build_errors,
            log_output=False,
        )

        return extracted_build_errors


def _extract_build_errors_c(full_log: str) -> str:
    with NamedTemporaryFile() as f:
        f.write(bytes(full_log, "utf-8"))
        f.flush()
        try:
            # @TODO: make sure that this function considers all the possible compiler cases (e.g., gcc/g++/clang, Makefile, CMake, etc..)
            stdout, _ = run_command(
                (f"cat {f.name} | grep -A 4 -E 'error:|warning:|note:'", Path("."))
            )
        except CommandInteractionError:
            return full_log

        if len(stdout) != 0:
            return stdout

    return full_log


def _extract_build_errors_jvm(full_log: str) -> str:
    with NamedTemporaryFile() as f:
        f.write(bytes(full_log, "utf-8"))
        f.flush()

        try:
            # @TODO: make sure that this function considers all the possible compiler cases (e.g., gcc/g++/clang, Makefile, CMake, etc..)
            stdout, _ = run_command(
                (f"cat {f.name} | grep -A 4 -E '\\[ERROR\\]|\\[error\\]'", Path("."))
            )
        except CommandInteractionError:
            return full_log

        if len(stdout) != 0:
            return stdout

    return full_log


def route_compile_feedback_patcher(state: PatchState) -> str:
    if len(state.requests) > 0:
        return "request_handler"

    match state.patch_stage:
        case PatchStage.INIT_ANALYSIS:
            pass
        case PatchStage.ANALYZE_ROOT_CAUSE:
            pass
        case PatchStage.ANALYZE_PROPERTY:
            pass
        case PatchStage.PATCH:
            pass
        case PatchStage.COMPILE_FEEDBACK:
            return "compile_feedback"
        case PatchStage.VULNERABLE_FEEDBACK:
            return "vulnerable_feedback"
        case PatchStage.TEST_FEEDBACK:
            return "test_feedback"
        case PatchStage.DONE:
            return END

    raise ValueError(f"{state.patch_stage} is not allowd for the patch stage")
