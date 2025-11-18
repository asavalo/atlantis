from pathlib import Path

from langchain.tools import tool  # type: ignore
from langchain_core.messages import HumanMessage
from langchain_core.tools.base import BaseTool
from python_file_system.directory.context_managers import changed_directory
from python_llm.agents.react import run_react_agent
from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.commons.interaction.functions import run_command
from crete.framework.agent.contexts import AgentContext
from crete.framework.agent.functions import store_debug_file
from crete.framework.coder.contexts import CoderContext
from crete.framework.coder.protocols import CoderProtocol
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.language_parser.functions import get_declaration_by_name
from crete.framework.language_parser.models import LanguageNode
from crete.framework.tools.services import AddImportModuleTool


class MinimalCoder(CoderProtocol):
    """
    Use minimal LLM costs to generate a patch.
    It referred to claude code's diff generation process.
    """

    def __init__(
        self,
        agent_context: AgentContext,
        detection: Detection,
        environment: EnvironmentProtocol,
        llm_api_manager: LlmApiManager,
        fault_location: FaultLocation,
        backup_llm_api_manager: LlmApiManager | None = None,
    ):
        super().__init__(agent_context, detection)

        self._environment = environment
        self._llm_api_manager = llm_api_manager
        self._backup_llm_api_manager = backup_llm_api_manager
        self._fault_location = fault_location

    def run(self, context: CoderContext, prompt: str) -> bytes | None:
        context["logger"].info("Running minimal coder ...")

        file_path = self._fault_location.file
        function_name = self._fault_location.function_name
        if function_name is None:
            return None

        node = _get_function_node(self._agent_context, file_path, function_name)
        if node is None:
            context["logger"].warning("Could not find the function node")
            return None

        tools = self._get_tools(self._agent_context, node)

        messages = [HumanMessage(prompt)]
        response = run_react_agent(
            self._llm_api_manager,
            tools,
            messages,
            backup_llm_api_manager=self._backup_llm_api_manager,
        )
        if response is None:
            return None
        store_debug_file(
            self._agent_context,
            "minimal_coder_response.txt",
            response,
        )

        if diff := self._resolve_patch_diff():
            store_debug_file(
                self._agent_context,
                "minimal_coder_diff.diff",
                diff.decode(errors="replace"),
            )
            return diff
        return None

    def _get_tools(
        self,
        context: AgentContext,
        node: LanguageNode,
    ) -> list[BaseTool]:
        @tool
        def view_function(function_name: str) -> str:
            """
            View the function
            """
            context["logger"].info(f"[TOOL CALL] view_function: {function_name}")
            assert function_name == self._fault_location.function_name
            context["logger"].info(f"[TOOL RETURN] view_function: {function_name}")
            return node.text

        @tool
        def edit_function(function_name: str, old_string: str, new_string: str):
            """
            Edit the function

            Args:
                function_name: The name of the function to edit
                old_string: The string to replace
                new_string: The new string to replace the old_string

            Returns:
                A message indicating whether the function was edited successfully

            Usage:
            - Edit the function by providing the function name, old string, and new string
            - old_string must be unique within the function, and must match the function contents exactly, including all whitespace and indentation
            - new_string is the edited text to replace the old_string

            """
            context["logger"].info(f"[TOOL CALL] edit_function: {function_name}")
            assert function_name == self._fault_location.function_name
            file_path = self._fault_location.file
            with changed_directory(context["pool"].source_directory):
                if not file_path.is_absolute():
                    file_path = context["pool"].source_directory / file_path
                original_text = file_path.read_text(errors="replace")
                new_text = original_text.replace(old_string, new_string)
                if new_text == original_text:
                    return "No changes were made - the old_string was not found in the file"
                file_path.write_text(new_text)
            context["logger"].info(f"[TOOL RETURN] edit_function: {function_name}")
            return "Successfully edited the function"

        tools = [
            view_function,
            edit_function,
        ]
        if self._detection.language == "jvm":
            tools.append(AddImportModuleTool(context, self._environment))
        return tools

    def _resolve_patch_diff(self) -> bytes | None:
        file_path = self._fault_location.file
        if not file_path.is_absolute():
            file_path = self._agent_context["pool"].source_directory / file_path
        with changed_directory(self._agent_context["pool"].source_directory):
            stdout, _ = run_command((f"git diff {file_path}", Path(".")))
            return stdout.encode() if stdout else None


def _get_function_node(
    context: AgentContext, file_path: Path, function_name: str
) -> LanguageNode | None:
    declaration = get_declaration_by_name(
        context["language_parser"],
        context,
        file_path,
        function_name,
    )
    if declaration is None:
        return None
    return declaration[1]
