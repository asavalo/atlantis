from __future__ import annotations

import copy
import os
from pathlib import Path

from dotenv import load_dotenv
from p4 import (
    AIxCCEnvironment,
    BaseClient,
    BaseEraserPolicy,
    BaseTool,
    generate_patch_using_langchain,
)
from p4_core.pattern.protocols import BasePattern
from p4_core.policy.models import AssistantMessage, Prompt
from p4_core.scope.protocols import Scope
from python_file_system.directory.context_managers import changed_directory
from python_global import GLOBAL_EXECUTABLE_FILE, GTAGS_EXECUTABLE_FILE
from python_llm.api.actors import LlmApiManager

from crete.atoms.action import NoPatchAction
from crete.atoms.detection import Detection
from crete.commons.interaction.functions import run_command
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.protocols import AgentProtocol


class AdaptationClient(BaseClient[LlmApiManager]):
    def __init__(self, adapter_base_url: str, vllm_base_url: str):
        self._adapter_base_url = adapter_base_url
        self._vllm_base_url = vllm_base_url

    @staticmethod
    def from_environment(
        key_of_adapter_base_url: str = "ADAPTER_API_BASE",
        key_of_vllm_base_url: str = "VLLM_API_BASE",
    ):
        load_dotenv(override=True)
        return AdaptationClient(
            adapter_base_url=os.environ[key_of_adapter_base_url],
            vllm_base_url=os.environ[key_of_vllm_base_url],
        )

    def _as(self, id: str) -> LlmApiManager:
        return LlmApiManager(
            model=id,
            api_key="sk-foobar",  # FIXME: Currently authorization is not used in the API
            base_url=self._vllm_base_url,
        )


class EraserAgent(AgentProtocol):
    def __init__(
        self,
        adaptation_client: BaseClient[LlmApiManager],
        llm_api_manager_for_patching: LlmApiManager,
        fallback_llm_api_manager_for_retrieval: LlmApiManager,
        tools: list[BaseTool],
        patterns: list[BasePattern],
        episode_length: int,
    ):
        self._adaptation_client = adaptation_client
        self._llm_api_manager = llm_api_manager_for_patching
        self._fallback_llm_api_manager_for_retrieval = (
            fallback_llm_api_manager_for_retrieval
        )
        self._tools = tools
        self._patterns = patterns
        self._episode_length = episode_length

    def act(self, context: AgentContext, detection: Detection):
        crash_log = context["crash_log_analyzer"].analyze(context, detection)
        assert crash_log is not None

        with changed_directory(context["pool"].source_directory):
            run_command(("git restore --source=HEAD :/", Path(".")))
            run_command((str(GTAGS_EXECUTABLE_FILE), Path(".")))

        def scope_builder(_: None) -> Scope:
            return {
                "source_directory": context["pool"].source_directory,
                "global_executable": GLOBAL_EXECUTABLE_FILE,
                "initial_crash_log": crash_log.decode(errors="ignore"),
            }

        environment = AIxCCEnvironment(
            tools=self._tools,
            episode_length=self._episode_length,
            scope_builder=scope_builder,
        )
        observation = environment.reset(None)
        previous_observation = copy.deepcopy(observation)

        llm_api_manager_for_retrieval = self._fallback_llm_api_manager_for_retrieval
        policy = EraserPolicy(
            patterns=self._patterns,
            llm_api_manager=llm_api_manager_for_retrieval,
        )
        done = False
        while not done:
            action = policy.act(observation, previous_observation)
            context["logger"].debug(f"Action: {action}")
            next_observation, terminated, truncated = environment.step(
                action=action,
                observation=observation,
                context=None,
            )
            context["logger"].debug(f"Next observation: {next_observation}")

            done = terminated or truncated
            previous_observation = copy.deepcopy(observation)
            observation = next_observation

        try:
            relative_patches, _ = generate_patch_using_langchain(
                documents=observation,
                source_directory=context["pool"].source_directory,
                chat_model=self._llm_api_manager.langchain_litellm(),
            )

            for relative_path, text in relative_patches.items():
                absolute_path = context["pool"].source_directory / relative_path

                if not absolute_path.is_file():
                    context["logger"].warning(
                        f"Patch file {relative_path} does not exist or is not a file."
                    )
                    continue

                absolute_path.write_text(text, encoding="utf-8")

            with changed_directory(context["pool"].source_directory):
                diff, _ = run_command(
                    ("git diff", Path(".")),
                )
                run_command(("git restore --source=HEAD :/", Path(".")))

            if diff.strip() == "":
                yield NoPatchAction()
            else:
                context["logger"].info(f"Generated diff: {diff}")
                yield context["evaluator"].evaluate(context, diff.encode(), detection)

        except ValueError as e:
            context["logger"].error(f"Error generating patch: {e}")

            yield NoPatchAction()


class EraserPolicy(BaseEraserPolicy):
    def __init__(
        self,
        patterns: list[BasePattern],
        llm_api_manager: LlmApiManager,
    ):
        super().__init__(patterns)
        self._llm_api_manager = llm_api_manager

    def completions_from_prompts(self, prompts: list[Prompt]) -> list[AssistantMessage]:
        result: list[AssistantMessage] = []

        with self._llm_api_manager.openai_chat_completion_create() as create:
            for prompt in prompts:
                message = create(messages=prompt).choices[0].message.content
                assert message is not None
                result.append(
                    {
                        "role": "assistant",
                        "content": message,
                    }
                )

        return result
