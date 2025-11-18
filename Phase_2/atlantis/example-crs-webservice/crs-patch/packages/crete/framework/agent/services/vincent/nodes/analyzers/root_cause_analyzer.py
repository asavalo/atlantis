from typing import Any
import re
from crete.framework.agent.services.vincent.nodes.llm_node import LLMNode
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)
from crete.framework.agent.services.vincent.functions import (
    create_prompt,
    extract_requests_in_chat,
    send_and_update_llm,
    get_last_chat,
)
from python_llm.api.actors import LlmApiManager
from crete.framework.agent.functions import store_debug_file


class RootCauseAnalyzer(LLMNode):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)

        self.is_instructed: bool = False

    def __call__(self, state: PatchState) -> dict[str, Any]:
        assert state.patch_stage == PatchStage.ANALYZE_ROOT_CAUSE

        if not self.is_instructed:
            self._instruct_llm_with_guideline(state)
            return self._get_dict_from_state(state)

        # All the LLM requests must be resolved before creating a report
        assert len(state.requests) == 0

        state.rca_report = self._create_rca_report(state)

        if state.rca_report is None:
            state.rca_report = self._handle_wrong_report(state)
            assert state.rca_report is not None

        store_debug_file(
            self.context, "rca-report.txt", state.rca_report, log_output=False
        )

        # Now proceed to program property analysis step.
        state.patch_stage = PatchStage.ANALYZE_PROPERTY

        return self._get_dict_from_state(state)

    def _instruct_llm_with_guideline(self, state: PatchState):
        self.context["logger"].info("root cause analysis stage entered")

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("root_cause_analyzer_init"),
        )

        state.requests = extract_requests_in_chat(get_last_chat(state.messages))

        self.is_instructed = True

    def _create_rca_report(self, state: PatchState) -> str | None:
        rca_report = _extract_rca_report(get_last_chat(state.messages))

        if rca_report is None:
            self.context["logger"].warning(
                "RCA report has not been received from LLM yet. Create it."
            )
            send_and_update_llm(
                self.context,
                state.messages,
                self.llm,
                create_prompt("root_cause_analyzer_report"),
            )
            rca_report = _extract_rca_report(get_last_chat(state.messages))

        return rca_report

    def _handle_wrong_report(self, state: PatchState) -> str | None:
        self.context["logger"].warning(
            "Invalid rca report format received from the LLM. Re-generate rca report"
        )

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("check_wrong_rca_report"),
        )
        return _extract_rca_report(get_last_chat(state.messages))


def _extract_rca_report(message: str) -> str | None:
    pattern = r"\[RCA\]\n(.*?)\[/RCA\]"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, message, re.DOTALL)

    if len(matches) == 0:
        return None

    return matches[0]


def route_root_cause_analyzer(state: PatchState) -> str:
    if len(state.requests) > 0:
        return "request_handler"

    match state.patch_stage:
        case PatchStage.INIT_ANALYSIS:
            pass
        case PatchStage.ANALYZE_ROOT_CAUSE:
            return "root_cause_analyzer"
        case PatchStage.ANALYZE_PROPERTY:
            return "property_analyzer"
        case PatchStage.PATCH:
            pass
        case PatchStage.COMPILE_FEEDBACK:
            pass
        case PatchStage.VULNERABLE_FEEDBACK:
            pass
        case PatchStage.TEST_FEEDBACK:
            pass
        case PatchStage.DONE:
            pass

    raise ValueError(f"{state.patch_stage} is not allowd for RootCauseAnalyzer")
