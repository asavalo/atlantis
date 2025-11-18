from pathlib import Path
from tree_sitter import Parser
from typing import TypeAlias
from tree_sitter import Node
from ..base_inspector import BaseInspector
from crete.framework.language_parser.services.ctags.models import (
    TagKind,
    CtagEntry,
)
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
    CodeSnippet,
)
from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_text_lines_from_file,
    get_first_comment_node,
)

from .node_finders.class_node_finder import ClassNodeFinder
from .node_finders.enum_node_finder import EnumNodeFinder
from .node_finders.field_node_finder import FieldNodeFinder
from .node_finders.method_node_finder import MethodNodeFinder
from .node_finders.interface_node_finder import InterfaceNodeFinder
from .node_finders.annotation_node_finder import AnnotationNodeFinder
from .node_finders.enum_constant_node_finder import EnumConstantNodeFinder

FAIL_SAFE_CONTEXT_WINDOW = 50

NodeFinder: TypeAlias = (
    ClassNodeFinder
    | EnumNodeFinder
    | MethodNodeFinder
    | FieldNodeFinder
    | InterfaceNodeFinder
    | AnnotationNodeFinder
    | EnumConstantNodeFinder
)


class JavaInspector(BaseInspector):
    def __init__(self, src_path: Path, proj_path: Path, parser: Parser):
        super().__init__(src_path, proj_path, parser)

        if not src_path.exists():
            raise FileNotFoundError(f'"{src_path}" does not exist')

        self.class_finder = ClassNodeFinder()
        self.enum_finder = EnumNodeFinder()
        self.method_finder = MethodNodeFinder()
        self.field_finder = FieldNodeFinder()
        self.interface_finder = InterfaceNodeFinder()
        self.annotation_finder = AnnotationNodeFinder()
        self.enum_constant_finder = EnumConstantNodeFinder()

        self._parse()

    def _parse(self):
        self.tree = self.parser.parse(self.src_path.read_bytes())

        self._prepare_nodes_for_finders(self.tree.root_node)

    def _prepare_nodes_for_finders(self, node: Node):
        if node.type == "ERROR":
            return

        if self.class_finder.is_interesting(node):
            self.class_finder.add_node(node)
        elif self.method_finder.is_interesting(node):
            self.method_finder.add_node(node)
        elif self.interface_finder.is_interesting(node):
            self.interface_finder.add_node(node)
        elif self.annotation_finder.is_interesting(node):
            self.annotation_finder.add_node(node)
        elif self.enum_finder.is_interesting(node):
            self.enum_finder.add_node(node)
        elif self.field_finder.is_interesting(node):
            self.field_finder.add_node(node)
        elif self.enum_constant_finder.is_interesting(node):
            self.enum_constant_finder.add_node(node)

        for child in node.children:
            self._prepare_nodes_for_finders(child)

    def _get_method_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.method_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_enum_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.enum_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_class_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.class_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_field_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.field_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_interface_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.interface_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_annotation_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.annotation_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_enum_constant_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.enum_constant_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def get_definition(
        self, ctag_entry: CtagEntry, print_line: bool = True
    ) -> CodeQueryResult | None:
        match ctag_entry.kind:
            case TagKind.CLASS:
                snippet = self._get_class_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.METHOD:
                snippet = self._get_method_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.FIELD:
                snippet = self._get_field_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.ENUM:
                snippet = self._get_enum_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.INTERFACE:
                snippet = self._get_interface_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.ANNOTATION:
                snippet = self._get_annotation_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.ENUMCONSTANT:
                snippet = self._get_enum_constant_definition(
                    ctag_entry, comment=True, print_line=print_line
                )
            case TagKind.PACKAGE:
                # @TODO: Do we need to implement this part?? More experiment is requried.
                snippet = None
                # snippet_tuple = self._get_package_definition(
                #     ctag_entry, comment=True, print_line=print_line
                # )
            case _:
                raise ValueError(f"{ctag_entry.kind} is not supported by Java")

        is_tree_sitter = True
        if snippet is None:
            snippet = self._get_definition_fail_safe(
                ctag_entry, ctag_entry.line, print_line=print_line
            )
            is_tree_sitter = False

        assert snippet is not None

        return CodeQueryResult(
            abs_src_path=self.src_path,
            src_path=self.src_path.relative_to(self.proj_path),
            snippet=snippet,
            is_tree_sitter=is_tree_sitter,
        )

    def _get_definition_fail_safe(
        self, ctag_entry: CtagEntry, line_num: int, print_line: bool = True
    ) -> CodeSnippet | None:
        # @TODO: add other fail-safe methods like CppInspector
        # snippet_tuple = self._fail_safe_get_surrounding_node_snippet(
        #     ctag_entry, print_line=print_line
        # )

        # if snippet_tuple is not None:
        #     return snippet_tuple

        return self._fail_safe_get_surrounding_lines(
            ctag_entry.abs_src_path, line_num, print_line=print_line
        )

    def _fail_safe_get_surrounding_lines(
        self,
        src_path: Path,
        line_num: int,
        print_line: bool = True,
        window: int = FAIL_SAFE_CONTEXT_WINDOW,
    ) -> CodeSnippet | None:
        start_line = line_num - 3  # a little room before the specified line_num
        end_line = line_num + window
        if start_line < 1:
            start_line = 1

        return get_text_lines_from_file(
            src_path, start_line, end_line, print_line=print_line
        )

    def get_reference_snippet(
        self, line_num: int, print_line: bool = True
    ) -> CodeQueryResult | None:
        target_node = self._find_interesting_node_with_line(line_num)

        is_tree_sitter = True
        if target_node is None:
            snippet = self._fail_safe_get_surrounding_lines(
                self.src_path, line_num, print_line=print_line, window=10
            )
            is_tree_sitter = False
        else:
            snippet = self.generate_snippet_with_nodes(
                target_node, target_node, print_line=print_line
            )

        if snippet is None:
            return None

        return CodeQueryResult(
            abs_src_path=self.src_path,
            src_path=self.src_path.relative_to(self.proj_path),
            snippet=snippet,
            is_tree_sitter=is_tree_sitter,
        )

    def _find_interesting_node_with_line(self, line_num: int) -> Node | None:
        cur_node = self._find_node_at_line(line_num)

        while cur_node is not None:
            if self.class_finder.has_node(cur_node):
                return cur_node
            elif self.method_finder.has_node(cur_node):
                return cur_node
            elif self.enum_finder.has_node(cur_node):
                return cur_node
            elif self.field_finder.has_node(cur_node):
                return cur_node
            elif self.interface_finder.has_node(cur_node):
                return cur_node
            elif self.annotation_finder.has_node(cur_node):
                return cur_node
            elif self.enum_constant_finder.has_node(cur_node):
                return cur_node

            if cur_node.parent is None:
                return None

            cur_node = cur_node.parent

        return None

    def generate_snippet_with_nodes(
        self,
        start_node: Node,
        end_node: Node,
        comment: bool = True,
        print_line: bool = True,
    ) -> CodeSnippet | None:
        if comment:
            # also include comments surrounding the target node to assist LLMs
            start_node = get_first_comment_node(start_node)

        start_line = start_node.start_point[0] + 1
        end_line = end_node.end_point[0] + 1

        return get_text_lines_from_file(
            self.src_path,
            start_line,
            end_line,
            print_line=print_line,
        )
