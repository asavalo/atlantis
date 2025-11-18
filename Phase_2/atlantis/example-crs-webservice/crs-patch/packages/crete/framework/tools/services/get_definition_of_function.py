from pathlib import Path

from langchain_core.tools import BaseTool

from crete.atoms.detection import Detection
from crete.framework.code_inspector.functions import get_function_definition_node
from crete.framework.insighter.contexts import InsighterContext
from crete.utils.tools.callbacks import LoggingCallbackHandler


class GetDefinitionOfFunctionTool(BaseTool):
    name: str = "get_definition_of_function"
    description: str = "Get the definition of the function at the given position."

    def __init__(self, context: InsighterContext, detection: Detection):
        super().__init__(
            callbacks=[LoggingCallbackHandler(context)],
        )
        self._context = context
        self._detection = detection

    def _run(self, file: str, line: int, function_name: str) -> str:
        """
        Get the definition of the function at the given position.
        """
        function_node = get_function_definition_node(
            self._context, self._detection, Path(file), line, function_name
        )
        assert function_node is not None, "Failed to get definition"
        return function_node.text
