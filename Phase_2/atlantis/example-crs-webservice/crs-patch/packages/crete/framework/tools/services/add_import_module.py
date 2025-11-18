from pathlib import Path
from typing import cast

from langchain_core.tools import BaseTool
from tree_sitter import Node

from crete.framework.environment.functions import resolve_project_path
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.language_parser.services.tree_sitter import (
    TreeSitterLanguageParser,
)
from crete.utils.tools.callbacks import LoggingCallbackHandler


class AddImportModuleTool(BaseTool):
    name: str = "add_import_module"
    description: str = """Add a module import statement to the file.

    Usage:
    - The module_name parameter must be a valid module name
    - The file_path parameter must be an absolute path, not a relative path

    Example:
    - module_name: java.util.ArrayList
    - file_path: /path/to/file.java
"""

    def __init__(
        self,
        context: InsighterContext,
        environment: EnvironmentProtocol,
    ):
        super().__init__(callbacks=[LoggingCallbackHandler(context)])
        self._context = context
        self._environment = environment

    def _run(self, module_name: str, file_path: str) -> str:
        resolved_path = resolve_project_path(
            Path(file_path), self._context["pool"].source_directory
        )
        if not resolved_path:
            return f"File does not exist: {file_path}"

        file_content = resolved_path.read_text(errors="replace")
        import_statement = f"import {module_name};"

        if import_statement in file_content:
            return "Import already present."

        parser = cast(TreeSitterLanguageParser, self._context["language_parser"])
        root = parser.parse(self._context, Path(resolved_path)).root_node
        assert root.text is not None

        code = root.text.decode(errors="replace")
        insert_pos = _find_where_to_add_import(root)
        new_code = code[:insert_pos] + f"\n{import_statement}" + code[insert_pos:]

        Path(resolved_path).write_text(new_code)
        return "Import added successfully."


def _find_import(node: Node) -> list[Node]:
    imports: list[Node] = []
    for child in node.children:
        if child.type == "import_declaration":
            imports.append(child)
    return imports


def _find_package(node: Node) -> Node | None:
    for child in node.children:
        if child.type == "package_declaration":
            return child
    return None


def _find_where_to_add_import(node: Node) -> int:
    imports = _find_import(node)
    if len(imports) > 0:
        insert_pos = imports[-1].end_byte
    elif pkg := _find_package(node):
        insert_pos = pkg.end_byte
    else:
        insert_pos = 0
    return insert_pos
