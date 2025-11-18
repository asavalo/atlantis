import inspect
from typing import Literal

from langchain_core.language_models import BaseChatModel

from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.services.redia.states import RediaState
from crete.framework.coder.services.redia import RediaCoder
from crete.framework.fault_localizer.functions import fault_locations_to_files
from crete.framework.fault_localizer.protocols import FaultLocalizerProtocol


class RediaFaultLocalizerNode:
    def __init__(
        self,
        context: AgentContext,
        detection: Detection,
        fault_localizer: FaultLocalizerProtocol,
    ) -> None:
        self._context = context
        self._detection = detection
        self._fault_localizer = fault_localizer

    def __call__(self, state: RediaState) -> RediaState:
        return {
            "messages": state["messages"],
            "target_files": fault_locations_to_files(
                self._fault_localizer.localize(self._context, self._detection).locations
            ),
            "diff": state["diff"],
            "action": state["action"],
        }


class RediaCoderNode:
    def __init__(
        self, context: AgentContext, detection: Detection, model: BaseChatModel
    ) -> None:
        self._context = context
        self._detection = detection
        self._model = model

    def __call__(self, state: RediaState) -> RediaState:
        redia_coder = RediaCoder(
            self._context,
            self._detection,
            self._model,
            state["target_files"],
        )

        human_message_prompt_text_template = inspect.cleandoc(
            """
            You are given a instruction to fix a vulnerability and a list of files that contain code that needs to be fixed.
            Please fix the code in the files and return the fixed code.

            {format_instructions}

            {prompt}

            # Files to edit
            {files}
            """
        )

        diff = redia_coder.run(self._context, human_message_prompt_text_template)

        self._context["logger"].info(f"Suggested diff: {diff}")

        return {
            "messages": state["messages"],
            "target_files": state["target_files"],
            "diff": diff if diff is not None else b"",
            "action": state["action"],
        }


class RediaEvaluatorNode:
    def __init__(self, context: AgentContext, detection: Detection) -> None:
        self._context = context
        self._detection = detection

    def __call__(self, state: RediaState) -> RediaState:
        action = self._context["evaluator"].evaluate(
            self._context, state["diff"], self._detection
        )
        return {
            "messages": state["messages"],
            "target_files": state["target_files"],
            "diff": state["diff"],
            "action": action,
        }


def evaluator_condition(state: RediaState) -> Literal["fault_localizer", "__end__"]:
    # TODO: Use this kind of condition for feedback.
    # if isinstance(state["action"], SoundDiffAction):
    #     return "__end__"
    # else:
    #     return "fault_localizer"
    # XXX: Just ending for now.
    return "__end__"
