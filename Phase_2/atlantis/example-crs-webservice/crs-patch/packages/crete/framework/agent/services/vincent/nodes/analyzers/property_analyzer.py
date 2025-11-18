from typing import Any
import inspect
import re
from crete.framework.agent.services.vincent.nodes.llm_node import LLMNode
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)
from crete.framework.agent.services.vincent.functions import (
    extract_requests_in_chat,
    create_prompt,
    send_and_update_llm,
    get_last_chat,
)
from python_llm.api.actors import LlmApiManager
from crete.framework.agent.functions import store_debug_file


class PropertyAnalyzer(LLMNode):
    def __init__(self, llm_api_manager: LlmApiManager):
        super().__init__(llm_api_manager)

        self.is_instructed: bool = False

    def __call__(self, state: PatchState) -> dict[str, Any]:
        assert state.patch_stage == PatchStage.ANALYZE_PROPERTY

        if not self.is_instructed:
            self._instruct_llm_with_guideline(state)
            return self._get_dict_from_state(state)

        # All the LLM requests must be resolved before creating a report
        assert len(state.requests) == 0

        state.properties = self._create_property_report(state)

        if state.properties is None:
            state.properties = self._handle_wrong_property_report(state)
            assert state.properties is not None

        state.patch_stage = PatchStage.PATCH

        return self._get_dict_from_state(state)

    def _instruct_llm_with_guideline(self, state: PatchState):
        self.context["logger"].info("***** property analyzer phase *****")

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("property_analyzer_init"),
        )

        state.requests = extract_requests_in_chat(get_last_chat(state.messages))

        self.is_instructed = True

    def _create_property_report(self, state: PatchState) -> list[str] | None:
        properties = _extract_properties(get_last_chat(state.messages))

        if properties is None:
            self.context["logger"].error(
                "Property analysis report has not been received from LLM. Instruct LLM to provide it."
            )
            send_and_update_llm(
                self.context,
                state.messages,
                self.llm,
                create_prompt("property_analyzer_report"),
            )
            properties = _extract_properties(get_last_chat(state.messages))

        store_debug_file(
            self.context,
            "property-report.txt",
            get_last_chat(state.messages),
            log_output=False,
        )

        return properties

    def _handle_wrong_property_report(self, state: PatchState) -> list[str] | None:
        self.context["logger"].error(
            "Invalid property analysis report received from the LLMs. Re-generate property report"
        )

        send_and_update_llm(
            self.context,
            state.messages,
            self.llm,
            create_prompt("check_wrong_property_report"),
        )

        report = get_last_chat(state.messages)
        store_debug_file(
            self.context, "property-report-fixed.txt", report, log_output=False
        )

        return _extract_properties(report)


def _extract_properties(message: str) -> list[str] | None:
    pattern = r"\[PROP\](.*?)\[/PROP\]"

    # Use re.search to find the first occurrence of the pattern
    matches = re.findall(pattern, message, re.DOTALL)

    if len(matches) == 0:
        return None

    return [inspect.cleandoc(match) for match in matches]


def route_property_analyzer(state: PatchState) -> str:
    if len(state.requests) > 0:
        return "request_handler"

    match state.patch_stage:
        case PatchStage.INIT_ANALYSIS:
            pass
        case PatchStage.ANALYZE_ROOT_CAUSE:
            pass
        case PatchStage.ANALYZE_PROPERTY:
            return "property_analyzer"
        case PatchStage.PATCH:
            return "patcher"
        case PatchStage.COMPILE_FEEDBACK:
            pass
        case PatchStage.VULNERABLE_FEEDBACK:
            pass
        case PatchStage.TEST_FEEDBACK:
            pass
        case PatchStage.DONE:
            pass

    raise ValueError(f"{state.patch_stage} is not allowd for PropertyAnalyzer")
