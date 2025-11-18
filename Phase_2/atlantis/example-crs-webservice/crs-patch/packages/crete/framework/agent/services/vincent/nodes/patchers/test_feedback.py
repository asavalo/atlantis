from typing import Any
from pathlib import Path
from langgraph.graph import (  # pylint: disable=import-error, no-name-in-module
    END,
)
from crete.framework.agent.services.vincent.functions import (
    create_prompt,
    extract_requests_in_chat,
    get_last_chat,
    send_and_update_llm,
)
from crete.framework.agent.services.vincent.nodes.patchers.globals import (
    DEFAULT_MAXIMUM_FEEDBACK_THRESHOLD,
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)

from .patcher import Patcher
from python_llm.api.actors import LlmApiManager
from crete.framework.agent.functions import store_debug_file
from tempfile import NamedTemporaryFile
from crete.commons.interaction.functions import run_command


def _get_jvm_maven_test_log(full_log: str) -> str | None:
    # JVM test pattern string (ref: https://maven.apache.org/surefire/maven-surefire-plugin/)
    #     [INFO] -------------------------------------------------------
    #     [INFO]  T E S T S
    #     [INFO] -------------------------------------------------------
    if "surefire" in full_log and "[INFO]  T E S T S" in full_log:
        with NamedTemporaryFile() as f:
            f.write(bytes(full_log, "utf-8"))
            f.flush()

            # @TODO: Does this handle all the JVM internal test format in AIxCC?
            stdout, _ = run_command(
                (f"cat {f.name} | grep -A 30 -E '\\[ERROR\\]'", Path("."))
            )

            return stdout

    return None


class TestFeedbackPatcher(Patcher):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)

    def __call__(self, state: PatchState) -> dict[str, Any]:
        if state.patch_stage != PatchStage.TEST_FEEDBACK:
            raise RuntimeError

        assert state.detection is not None

        if state.feedback_cnt > DEFAULT_MAXIMUM_FEEDBACK_THRESHOLD:
            self.context["logger"].error(
                f"TestFeedbackPatcher exceeded maximum iteration count: {DEFAULT_MAXIMUM_FEEDBACK_THRESHOLD}"
            )

            state.patch_stage = PatchStage.DONE
            return self._get_dict_from_state(state)

        self.context["pool"].restore(self.context)

        if not self.is_instructed:
            self.context["logger"].info(
                f"******* Test-feedback Patch Phase (feedback: {state.feedback_cnt}) *******"
            )
            self._instruct_llm_with_guideline(state)
            return self._get_dict_from_state(state)

        assert self.is_instructed
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
        test_log = None
        if self.detection.language == "jvm":
            test_log = _get_jvm_maven_test_log(
                getattr(state.action, "stdout", b"").decode(errors="replace")
                + getattr(state.action, "stderr", b"").decode(errors="replace")
            )

        if test_log is None:
            send_and_update_llm(
                self.context,
                state.messages,
                self.llm,
                create_prompt(
                    "instruct_test_feedback_patch",
                    {"DIFF": state.diff.decode(errors="replace")},
                ),
            )
        else:
            send_and_update_llm(
                self.context,
                state.messages,
                self.llm,
                create_prompt(
                    "instruct_test_feedback_patch_with_test_log",
                    {"DIFF": state.diff.decode(errors="replace"), "TEST_LOG": test_log},
                ),
            )

        state.requests = extract_requests_in_chat(get_last_chat(state.messages))
        self.is_instructed = True


def route_test_feedback_patcher(state: PatchState) -> str:
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
