import json
from pathlib import Path
from typing import Any, Iterator

from langchain_core.messages.utils import convert_to_openai_messages  # type: ignore
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import Action, NoPatchAction
from crete.atoms.detection import Detection
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.agent.services.multi_retrieval.states.patch_state import PatchState
from crete.framework.agent.services.multi_retrieval.workflows.system_guided_patch_workflow import (
    SystemGuidedPatchWorkflow,
)


class MultiRetrievalPatchAgent(AgentProtocol):
    def __init__(
        self,
        llm_api_manager: LlmApiManager,
        backup_llm_api_manager: LlmApiManager | None = None,
        recursion_limit: int = 64,
        max_n_evals: int = 4,
    ) -> None:
        self._llm_api_manager = llm_api_manager
        self._backup_llm_api_manager = backup_llm_api_manager
        self.recursion_limit = recursion_limit
        self.workflow = SystemGuidedPatchWorkflow(max_n_evals=max_n_evals)
        self.workflow.compile(llm=self._llm_api_manager.langchain_litellm())

    def act(self, context: AgentContext, detection: Detection) -> Iterator[Action]:
        self.workflow.update(context, detection)

        final_diff = None
        try:
            patch_state = self.workflow.invoke(
                PatchState(repo_path=str(context["pool"].source_directory)),
                {"recursion_limit": self.recursion_limit},
            )

            final_diff = patch_state["diff"]
            if "output_directory" in context:
                self._log_state_to_file(
                    context["output_directory"],
                    patch_state,
                    self._llm_api_manager.model,
                )
        except Exception as e:  # pylint: disable=broad-except
            context["logger"].warning(
                f"Error occurred while generating patch: {e}", exc_info=True
            )
            final_diff = self._patch_with_backup_llm(context)

        if final_diff is None or len(final_diff.strip()) == 0:
            yield NoPatchAction()
        else:
            yield context["evaluator"].evaluate(
                context, bytes(final_diff, "utf-8"), detection
            )

    def _patch_with_backup_llm(self, context: AgentContext) -> str | None:
        final_diff = None
        if self._backup_llm_api_manager is None:
            return final_diff
        context["logger"].info("MultiRetrieval patching with backup LLM...")
        try:
            self.workflow.set_llm(self._backup_llm_api_manager.langchain_litellm())
            patch_state = self.workflow.invoke(
                PatchState(repo_path=str(context["pool"].source_directory)),
                {"recursion_limit": self.recursion_limit},
            )
            final_diff = patch_state["diff"]
            if "output_directory" in context:
                self._log_state_to_file(
                    context["output_directory"],
                    patch_state,
                    self._backup_llm_api_manager.model,
                )
        except Exception as e:  # pylint: disable=broad-except
            context["logger"].error(
                f"Error occurred while generating patch(backup): {e}",
                exc_info=True,
            )
        return final_diff

    def _log_state_to_file(
        self, output_directory: Path, state: dict[str, Any] | Any, model: str
    ) -> None:
        saved_state: dict[str, list[dict[str, str] | str | int]] = {  # type: ignore
            "model": model,
            "messages": convert_to_openai_messages(state["messages"]),  # type: ignore
            "diff": state["diff"],
            "n_evals": state["n_evals"],
            "tests_log": state["tests_log"],
        }

        saved_content = json.dumps(saved_state, ensure_ascii=False, indent=4)
        with open(output_directory / "messages.json", "w", encoding="utf-8") as f:
            f.write(saved_content)
