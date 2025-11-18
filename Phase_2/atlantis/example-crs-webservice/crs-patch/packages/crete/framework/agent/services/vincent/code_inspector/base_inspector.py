from pathlib import Path
from tree_sitter import Parser
from tree_sitter import Node, Tree

from crete.framework.language_parser.services.ctags.models import (
    CtagEntry,
)
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
    CodeSnippet,
)


class BaseInspector:
    def __init__(self, src_path: Path, proj_path: Path, parser: Parser):
        self.src_path = src_path
        self.proj_path = proj_path
        self.parser = parser

        # tree-sitter's tree
        self.tree: Tree | None = None

    def _parse(self): ...

    def get_definition(
        self, ctag_entry: CtagEntry, print_line: bool = True
    ) -> CodeQueryResult | None: ...

    def get_definition_likely_lines(
        self, target_name: str
    ) -> list[tuple[int, int]]: ...

    def get_reference_snippet(
        self, line_num: int, print_line: bool = True
    ) -> CodeQueryResult | None: ...

    def generate_snippet_with_nodes(
        self,
        start_node: Node,
        end_node: Node,
        comment: bool = True,
        print_line: bool = True,
    ) -> CodeSnippet | None: ...

    def _get_snippet_from_node_default(
        self,
        target_node: Node,
        pattern: str,
        comment: bool = True,
        print_line: bool = True,
    ) -> CodeSnippet | None:
        snippet = self.generate_snippet_with_nodes(
            target_node, target_node, comment=comment, print_line=print_line
        )

        if snippet is None:
            return None

        if pattern not in snippet.text:
            return None

        return snippet

    def _find_node_at_line(self, line: int) -> Node | None:
        """
        Find the node located in `line`
        """
        assert self.tree is not None

        def _traverse_node_to_find_line(node: Node, line: int) -> Node | None:
            if node.type == "ERROR":
                return None

            if node.start_point[0] + 1 <= line <= node.end_point[0] + 1:
                for child in node.children:
                    result = _traverse_node_to_find_line(child, line)
                    if result is not None:
                        return result
                return node
            return None

        return _traverse_node_to_find_line(self.tree.root_node, line)
