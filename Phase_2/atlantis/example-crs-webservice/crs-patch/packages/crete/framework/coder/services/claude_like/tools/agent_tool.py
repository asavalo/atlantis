from pathlib import Path
from typing import Optional

from langchain_core.callbacks import CallbackManagerForToolRun
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import BaseTool, ToolException
from langchain_core.tools.base import ArgsSchema
from langgraph.errors import GraphRecursionError

from logging import Logger

from pydantic import BaseModel, Field
from python_llm.api.actors import LlmApiManager

from crete.framework.coder.services.claude_like.graph import ClaudeLikeGraph
from crete.framework.coder.services.claude_like.prompts import (
    DEFAULT_SYSTEM_ENVIRONMENT_PROMPT,
)
from crete.framework.coder.services.claude_like.tools.glob_tool import GlobTool
from crete.framework.coder.services.claude_like.tools.grep_tool import GrepTool
from crete.framework.coder.services.claude_like.tools.ls_tool import LSTool
from crete.framework.coder.services.claude_like.tools.view_tool import ViewTool
from crete.framework.coder.services.claude_like.prompts import TOOL_NAME

RECURSION_LIMIT = 50


class AgentInput(BaseModel):
    prompt: str = Field(description="The task to be performed by the agent")


class AgentTool(BaseTool):
    name: str = "dispatch_agent"
    description: str = """Run a new agent capable of using View, GlobTool, GrepTool, and LS tools to perform the task given in the prompt.

When to use this tool
- It is used to decompose complex tasks. (e.g., "What is the role of a specific function ~?" or "Which files contain the specific keyword ~?")
- DO NOT use for tasks solvable by a single tool (e.g., reading a few files).

What outputs is expected by this tool
- The agent returns the result of the task as a string. (e.g., when asked about the role of a specific file, it returns a description of the file's role.)

Notes
- The agent cannot use tools such as Replace or Edit to modify files.
- Always provide the agent with a detailed and specific task in the prompt.
"""
    args_schema: Optional[ArgsSchema] = AgentInput
    return_direct: bool = False

    def __init__(
        self,
        logger: Logger,
        source_directory: Path,
        llm_api_manager: LlmApiManager,
        llm_history_file: Path | None,
    ):
        super().__init__()
        self._logger = logger
        self._source_directory = source_directory
        self._llm_api_manager = llm_api_manager
        self._llm_history_file = llm_history_file

    def _run(
        self,
        prompt: str,
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> str:
        self._logger.info("[Tool Call] AgentTool")
        self._logger.info(f"prompt: {prompt}")

        agent_system_prompt = f"""You are an agent of {TOOL_NAME}, a tool for fixing software vulnerabilities. Use the provided tools to carry out the tasks requested by the user. Never include detailed explanations, prefixes, or suffixes in your responses, and always provide file paths as absolute paths.

Notes
- IMPORTANT: Be concise, direct, and to the point. Answer the question directly, using one-word responses when possible.
- DO NOT include introductions, explanations, or conclusions.
- NEVER add text before or after your answer. (e.g., "The answer is ~" or "The answer is as follows: ~")
- Include relevant file paths or code snippets in the response if necessary.
- You MUST complete all tasks within 20 tools invocations.
"""
        agent_system_prompt += DEFAULT_SYSTEM_ENVIRONMENT_PROMPT.format(
            source_directory=self._source_directory,
            model_name=self._llm_api_manager.model,
        )
        tools: list[BaseTool] = self.get_tools()
        messages: list[BaseMessage] = [
            HumanMessage(prompt),
            SystemMessage(agent_system_prompt),
        ]

        graph = ClaudeLikeGraph(
            self._logger,
            self._llm_api_manager.langchain_litellm(),
            tools,
        ).construct_graph()
        try:
            response = graph.invoke(
                {"messages": messages}, {"recursion_limit": RECURSION_LIMIT}
            )
        except GraphRecursionError:
            raise ToolException(
                f"Recursion limit of {RECURSION_LIMIT} reached without hitting a stop condition"
            )

        if self._llm_history_file is not None:
            with open(self._llm_history_file, "a") as f:
                f.write(f"{response}")

        last_message = response["messages"][-1]

        if not isinstance(last_message, AIMessage):
            raise ToolException("Last message was not an assistant message")
        if not isinstance(last_message.content, str):  # pyright: ignore[reportUnknownMemberType]
            raise ToolException("Last message was malformed")

        return last_message.content

    def get_tools(self) -> list[BaseTool]:
        return [
            ViewTool(self._logger, self._source_directory, is_subtool=True),
            GlobTool(self._logger, self._source_directory, is_subtool=True),
            GrepTool(self._logger, self._source_directory, is_subtool=True),
            LSTool(self._logger, self._source_directory, is_subtool=True),
        ]
