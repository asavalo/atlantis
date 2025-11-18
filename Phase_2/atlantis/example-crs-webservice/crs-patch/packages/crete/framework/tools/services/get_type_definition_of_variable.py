from pathlib import Path

from langchain_core.tools import BaseTool

from crete.atoms.detection import Detection
from crete.framework.code_inspector.functions import get_variable_type_definition_node
from crete.framework.insighter.contexts import InsighterContext
from crete.utils.tools.callbacks import LoggingCallbackHandler


class GetTypeDefinitionOfVariableTool(BaseTool):
    name: str = "get_type_definition_of_variable"
    description: str = "Get the type definition of the symbol at the given position."

    def __init__(self, context: InsighterContext, detection: Detection):
        super().__init__(
            callbacks=[LoggingCallbackHandler(context)],
        )
        self._context = context
        self._detection = detection

    def _run(self, file: str, line: int, variable_name: str) -> str:
        """
        Get the type definition of the symbol at the given position.
        """
        type_definition_node = get_variable_type_definition_node(
            self._context, self._detection, Path(file), line, variable_name
        )
        assert type_definition_node is not None, "Failed to get type definition"
        return type_definition_node.text
