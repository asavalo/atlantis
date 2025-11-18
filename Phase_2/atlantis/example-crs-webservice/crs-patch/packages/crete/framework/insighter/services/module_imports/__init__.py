from pathlib import Path

from crete.atoms.detection import Detection
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.language_parser.services.tree_sitter import (
    TreeSitterLanguageParser,
)


class ModuleImportsInsighter(InsighterProtocol):
    def __init__(self, file_path: Path):
        self._file_path = file_path

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        if detection.language != "jvm":
            context["logger"].warning(
                "ModuleImportsInsighter only supports Java language"
            )
            return None

        # Here we directly use TreeSitterLanguageParser, instead of using the language parser protocol.
        # This is because we need to use the tree-sitter node directly, and traverse the tree to find the imports.
        # LanguageNode does not support this.
        if not isinstance(context["language_parser"], TreeSitterLanguageParser):
            context["logger"].warning("No other language parser is supported yet.")
            return None

        tree = context["language_parser"].parse(context, self._file_path)
        import_statements: list[str] = []
        for node in tree.root_node.children:
            if (
                node.type in ["import_declaration", "static_import_declaration"]
                and node.text is not None
            ):
                import_statements.append(node.text.decode(errors="replace"))
        return "\n".join(import_statements)
