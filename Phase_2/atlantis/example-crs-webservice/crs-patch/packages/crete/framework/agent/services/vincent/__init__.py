import json
from pathlib import Path
from typing import Any, Iterator

from langchain_core.messages.utils import convert_to_openai_messages  # type: ignore
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import Action, NoPatchAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.agent.services.vincent.states.patch_state import PatchState
from packages.crete.framework.agent.services.vincent.workflows.vincent_workflow import (
    VincentWorkflow,
)

DEFAULT_MAX_RECURSION_LIMIT = 128


class VincentAgent(AgentProtocol):
    def __init__(
        self,
        llm_api_manager: LlmApiManager,
    ) -> None:
        self._llm_api_manager = llm_api_manager

        self.workflow = VincentWorkflow()
        self.workflow.compile(self._llm_api_manager)

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        self.workflow.update(context, detection)

        try:
            patch_state = self.workflow.invoke(
                PatchState(
                    detection=detection,
                ),
                {"recursion_limit": DEFAULT_MAX_RECURSION_LIMIT},
            )

            if "output_directory" in context:
                _log_state_to_file(context["output_directory"], patch_state)

            yield patch_state["action"]

        except Exception as e:  # pylint: disable=broad-except
            context["logger"].warning(
                f"Error occurred while generating patch: {e}", exc_info=True
            )

        yield NoPatchAction()


def _log_state_to_file(output_directory: Path, state: dict[str, Any] | Any) -> None:
    saved_state: dict[str, list[dict[str, str] | str | int]] = {
        "messages": convert_to_openai_messages(state["messages"]),  # type: ignore
        "diff": state["diff"].decode(errors="replace"),
        "action": state["action"].__class__.__name__,
    }

    saved_content = json.dumps(saved_state, ensure_ascii=False, indent=4)
    with open(output_directory / "messages.json", "w", encoding="utf-8") as f:
        f.write(saved_content)
