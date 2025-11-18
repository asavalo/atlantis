from contextlib import contextmanager

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent  # type: ignore
from python_file_system.directory.context_managers import changed_directory
from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.insighter.services.crash_log import CrashLogInsighter
from crete.framework.insighter.services.writeup.prompts import create_writeup_prompt
from crete.framework.tools.services import (
    GetCodeAroundLineTool,
    GetDefinitionOfFunctionTool,
    GetTypeDefinitionOfVariableTool,
    SearchCodeInFileTool,
)


class WriteupInsighter(InsighterProtocol):
    def __init__(self, llm_api_manager: LlmApiManager) -> None:
        self._llm_api_manager = llm_api_manager

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        crash_log = CrashLogInsighter().create(context, detection)
        if crash_log is None:
            context["logger"].warning("Failed to generate crash log")
            return None

        writeup_prompt = create_writeup_prompt(crash_log)
        inputs = {
            "messages": [
                HumanMessage(writeup_prompt),
            ]
        }

        with changed_directory(context["pool"].source_directory):
            with self._create_agent(
                context, detection, self._llm_api_manager.langchain_litellm()
            ) as agent_executor:
                response = agent_executor.invoke(inputs)
                writeup = response["messages"][-1].content

        context["logger"].info(f"Writeup: {writeup}")
        return writeup

    # Copied from coderover-k fault localizer
    @contextmanager
    def _create_agent(
        self, context: InsighterContext, detection: Detection, chat_model: BaseChatModel
    ):
        tools = [
            GetDefinitionOfFunctionTool(context, detection),
            GetTypeDefinitionOfVariableTool(context, detection),
            GetCodeAroundLineTool(context),
            # search_code,
            SearchCodeInFileTool(context),
        ]
        yield create_react_agent(chat_model, tools)
