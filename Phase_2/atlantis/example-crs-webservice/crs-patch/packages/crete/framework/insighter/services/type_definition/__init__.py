from crete.atoms.detection import Detection
from crete.framework.code_inspector.functions import (
    get_type_definition_of_variable,
    get_variable_declarations_in_function,
)
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.language_parser.models import LanguageNode


class TypeDefinitionInsighter(InsighterProtocol):
    def __init__(
        self,
        function_declaration: tuple[str, LanguageNode],
    ):
        self._function_name = function_declaration[0]
        self._function_node = function_declaration[1]

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        variable_declarations = get_variable_declarations_in_function(
            context, self._function_node
        )
        if not variable_declarations:
            context["logger"].warning("No variables found in function")
            return None

        return self._generate_insight(context, detection, variable_declarations)

    def _generate_insight(
        self,
        context: InsighterContext,
        detection: Detection,
        variable_declarations: list[tuple[str, LanguageNode]],
    ) -> str:
        insight = (
            f"Variables in method: {self._function_name}\nVariables declarations:\n"
        )

        for variable_declaration in variable_declarations:
            name, declaration = variable_declaration
            type_string = context["language_parser"].get_type_string_of_declaration(
                context, declaration.file, declaration
            )

            type_definition = get_type_definition_of_variable(
                context, detection, declaration
            )

            if type_definition is None:
                context["logger"].warning("Type definition not found for variable")
                insight += f"- name: {name}, type: {type_string}\n"
            else:
                insight += (
                    f"- name: {name}, type: {type_string}\n"
                    f"  typedef: {type_definition.text}\n"
                )

        return insight
