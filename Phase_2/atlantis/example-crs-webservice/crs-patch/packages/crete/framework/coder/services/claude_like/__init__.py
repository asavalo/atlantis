from pathlib import Path

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.errors import GraphRecursionError
from python_file_system.directory.context_managers import changed_directory
from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.commons.interaction.functions import run_command
from crete.framework.agent.contexts import AgentContext
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol
from crete.framework.coder.services.claude_like.prompts import (
    DEFAULT_SYSTEM_ENVIRONMENT_PROMPT,
    DEFAULT_SYSTEM_INSTRUCTION_PROMPT,
    INITIAL_SYSTEM_PROMPT,
    JVM_SPECIFIC_INSTRUCTIONS,
)
from crete.framework.coder.services.claude_like.tools import (
    AgentTool,
    EditTool,
    GlobTool,
    GrepTool,
    LSTool,
    ReplaceTool,
    ViewTool,
)

from crete.framework.coder.services.claude_like.graph import ClaudeLikeGraph

RECURSION_LIMIT = 90


class ClaudeLikeCoder(CoderProtocol):
    def __init__(
        self,
        agent_context: AgentContext,
        detection: Detection,
        llm_api_manager: LlmApiManager | None,
    ):
        super().__init__(agent_context, detection)
        self._logger = agent_context["logger"]
        self._llm_history_file = _prepare_llm_history_file(agent_context)
        self._llm_history_file = (
            self._llm_history_file.absolute() if self._llm_history_file else None
        )
        self._language = detection.language

        self._llm_api_manager = (
            llm_api_manager
            if llm_api_manager is not None
            else LlmApiManager.from_environment(
                model="claude-3-7-sonnet-20250219", custom_llm_provider="anthropic"
            )
        )

    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        tools = self.get_tools()

        with changed_directory(self._agent_context["pool"].source_directory):
            run_command(("git restore --source=HEAD :/", Path(".")))

            messages = self.get_message(prompt)
            graph = ClaudeLikeGraph(
                self._agent_context["logger"],
                self._llm_api_manager.langchain_litellm(),
                tools,
            ).construct_graph()

            try:
                response = graph.invoke(
                    {"messages": messages}, {"recursion_limit": RECURSION_LIMIT}
                )
                self.log_agent_history(str(response))
            except GraphRecursionError:
                context["logger"].info(
                    f"Recursion limit of {RECURSION_LIMIT} reached without hitting a stop condition"
                )

            return _git_diff().encode()

    def get_message(self, prompt: str) -> list[BaseMessage]:
        match self._language:
            case "jvm":
                language_specific_instructions = JVM_SPECIFIC_INSTRUCTIONS
            case _:
                language_specific_instructions = ""

        system_prompt = DEFAULT_SYSTEM_INSTRUCTION_PROMPT.format(
            language_specific_instructions=language_specific_instructions,
        ) + DEFAULT_SYSTEM_ENVIRONMENT_PROMPT.format(
            source_directory=self._agent_context["pool"].source_directory,
            model_name=self._llm_api_manager.model,
        )

        return [
            HumanMessage(prompt),
            SystemMessage(INITIAL_SYSTEM_PROMPT),
            SystemMessage(system_prompt),
        ]

    def get_tools(self) -> list[BaseTool]:
        return [
            AgentTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
                self._llm_api_manager,
                self._llm_history_file,
            ),
            GlobTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
            ),
            GrepTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
            ),
            LSTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
            ),
            ViewTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
            ),
            EditTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
            ),
            ReplaceTool(
                self._agent_context["logger"],
                self._agent_context["pool"].source_directory,
            ),
        ]

    def log_agent_history(self, history: str) -> None:
        self._logger.info(f"Agent history:\n{history}")
        if self._llm_history_file is not None:
            with open(self._llm_history_file, "a") as f:
                f.write(history)


def _prepare_llm_history_file(context: AgentContext) -> Path | None:
    if "output_directory" in context:
        llm_history_file = context["output_directory"] / ".claude_like_llm_history_log"
        if llm_history_file.exists():
            llm_history_file.unlink()
            llm_history_file.touch(exist_ok=True)
        return llm_history_file

    return None


def _git_diff():
    stdout, _ = run_command(("git diff", Path(".")))
    run_command(("git restore --source=HEAD :/", Path(".")))
    return stdout
