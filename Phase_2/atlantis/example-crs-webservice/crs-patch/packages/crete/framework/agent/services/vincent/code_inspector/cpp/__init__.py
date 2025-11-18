from tree_sitter import Parser
from tree_sitter import Tree, Node
from typing import TypeAlias
from pathlib import Path
from ..base_inspector import BaseInspector
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
    CodeSnippet,
)
from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_text_lines_from_file,
    get_first_comment_node,
)
from crete.framework.agent.services.vincent.functions import get_token_size
from crete.framework.language_parser.services.ctags.models import (
    TagKind,
    CtagEntry,
)

from .node_finders.function_node_finder import FunctionNodeFinder
from .node_finders.struct_union_node_finder import StructUnionNodeFinder
from .node_finders.macro_node_finder import MacroNodeFinder
from .node_finders.variable_node_finder import VariableNodeFinder
from .node_finders.typedef_node_finder import TypedefNodeFinder
from .node_finders.enum_node_finder import EnumNodeFinder
from .node_finders.enuerator_node_finder import EnumeratorNodeFinder
from .node_finders.class_node_finder import ClassNodeFinder


FAIL_SAFE_CONTEXT_WINDOW = 150
SAFE_SNIPPET_TOKEN_COUNT = 300
FUNCTION_BODY_CLOSING_PATTERN = "}\n"

NodeFinder: TypeAlias = (
    FunctionNodeFinder
    | StructUnionNodeFinder
    | MacroNodeFinder
    | VariableNodeFinder
    | TypedefNodeFinder
    | EnumNodeFinder
    | EnumeratorNodeFinder
    | ClassNodeFinder
)


class CppInspector(BaseInspector):
    def __init__(self, src_path: Path, proj_path: Path, parser: Parser):
        super().__init__(src_path, proj_path, parser)

        if not src_path.exists():
            raise FileNotFoundError(f'"{src_path}" does not exist')

        self.tree: Tree | None = None

        self.func_finder = FunctionNodeFinder()
        self.stuct_union_finder = StructUnionNodeFinder()
        self.variable_finder = VariableNodeFinder()
        self.typedef_finder = TypedefNodeFinder()
        self.enum_node_finder = EnumNodeFinder()
        self.enumerator_node_finder = EnumeratorNodeFinder()
        self.macro_finder = MacroNodeFinder()
        self.class_finder = ClassNodeFinder()

        self._parse()

    def _prepare_nodes_for_finders(self, node: Node):
        if node.type == "ERROR":
            return

        if self.func_finder.is_interesting(node):
            self.func_finder.add_node(node)
        elif self.stuct_union_finder.is_interesting(node):
            self.stuct_union_finder.add_node(node)
        elif self.enum_node_finder.is_interesting(node):
            self.enum_node_finder.add_node(node)
            self.enumerator_node_finder.add_node(node)
        elif self.macro_finder.is_interesting(node):
            self.macro_finder.add_node(node)
        elif self.typedef_finder.is_interesting(node):
            self.typedef_finder.add_node(node)
        elif self.variable_finder.is_interesting(node):
            self.variable_finder.add_node(node)

        for child in node.children:
            self._prepare_nodes_for_finders(child)

    def _parse(self):
        self.tree = self.parser.parse(self.src_path.read_bytes())

        self._prepare_nodes_for_finders(self.tree.root_node)

    def get_definition(
        self, ctag_entry: CtagEntry, print_line: bool = True
    ) -> CodeQueryResult | None:
        match ctag_entry.kind:
            case TagKind.FUNCTION:
                snippet = self._get_function_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.STRUCT:
                snippet = self._get_struct_union_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.UNION:
                snippet = self._get_struct_union_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.ENUMERATOR:
                snippet = self._get_enumerator_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.MACRO:
                snippet = self._get_macro_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.TYPEDEF:
                snippet = self._get_typedef_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.VARIABLE:
                snippet = self._get_variable_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.ENUM:
                snippet = self._get_enum_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.MEMBER:
                snippet = self._get_member_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.HEADER:
                snippet = self._get_header_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case TagKind.CLASS:
                snippet = self._get_class_definition(
                    ctag_entry, comment=False, print_line=print_line
                )
            case _:
                raise ValueError(f"{ctag_entry.kind} is not supported by C/C++")

        is_tree_sitter = True
        if snippet is None:
            snippet = self._get_definition_fail_safe(
                ctag_entry, ctag_entry.line, print_line=print_line
            )
            is_tree_sitter = False

        assert snippet is not None

        if get_token_size(snippet.text) > SAFE_SNIPPET_TOKEN_COUNT:
            snippet = self._handle_token_exceeded_snippet(snippet, ctag_entry)

        return CodeQueryResult(
            abs_src_path=self.src_path,
            src_path=self.src_path.relative_to(self.proj_path),
            snippet=snippet,
            is_tree_sitter=is_tree_sitter,
        )

    def get_definition_likely_lines(self, target_name: str) -> list[tuple[int, int]]:
        def _search_all_name_nodes_recursive(
            node: Node, target_name: str, found_nodes: list[Node]
        ):
            # Since we don't have ctags information, we have to inspect all the possible cases (e.g., function, macro, etc)...
            if self.func_finder.is_interesting(node):
                if self.func_finder.get_name(node) == target_name:
                    found_nodes.append(node)
            if self.macro_finder.is_interesting(node):
                if self.macro_finder.get_name(node) == target_name:
                    found_nodes.append(node)
            if self.stuct_union_finder.is_interesting(node):
                if self.stuct_union_finder.get_name(node) == target_name:
                    found_nodes.append(node)
            if self.typedef_finder.is_interesting(node):
                if self.typedef_finder.get_name(node) == target_name:
                    found_nodes.append(node)
            if self.variable_finder.is_interesting(node):
                if self.variable_finder.get_name(node) == target_name:
                    found_nodes.append(node)
            if self.enum_node_finder.is_interesting(node):
                if self.enum_node_finder.get_name(node) == target_name:
                    found_nodes.append(node)

            for child in node.children:
                _search_all_name_nodes_recursive(child, target_name, found_nodes)

        assert self.tree is not None

        definition_related_nodes: list[Node] = []
        _search_all_name_nodes_recursive(
            self.tree.root_node, target_name, definition_related_nodes
        )
        return [
            (node.start_point[0] + 1, node.end_point[0])
            for node in definition_related_nodes
        ]

    def _handle_token_exceeded_snippet(
        self, snippet: CodeSnippet, ctag_entry: CtagEntry
    ) -> CodeSnippet:
        match ctag_entry.kind:
            case TagKind.FUNCTION:
                return snippet
            case TagKind.STRUCT:
                return snippet
            case TagKind.UNION:
                return snippet
            case TagKind.ENUMERATOR:
                token_safe_snippet = self._fail_safe_get_surrounding_lines(
                    ctag_entry.abs_src_path, ctag_entry.line, window=10
                )
            case TagKind.MACRO:
                token_safe_snippet = self._fail_safe_get_surrounding_lines(
                    ctag_entry.abs_src_path, ctag_entry.line, window=10
                )
            case TagKind.TYPEDEF:
                return snippet
            case TagKind.VARIABLE:
                token_safe_snippet = self._fail_safe_get_surrounding_lines(
                    ctag_entry.abs_src_path, ctag_entry.line, window=10
                )
            case TagKind.ENUM:
                token_safe_snippet = self._fail_safe_get_surrounding_lines(
                    ctag_entry.abs_src_path, ctag_entry.line, window=10
                )
            case TagKind.MEMBER:
                token_safe_snippet = self._fail_safe_get_surrounding_lines(
                    ctag_entry.abs_src_path, ctag_entry.line, window=10
                )
            case TagKind.HEADER:
                token_safe_snippet = self._fail_safe_get_surrounding_lines(
                    ctag_entry.abs_src_path, ctag_entry.line, window=10
                )
            case TagKind.CLASS:
                return snippet
            case _:
                raise ValueError(f"{ctag_entry.kind} is not supported by C/C++")

        # Since we already have some snippet (i.e., `snippet`), we must be able to get a size-reduced snippet.
        assert token_safe_snippet is not None

        return token_safe_snippet

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

    def _get_function_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.func_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_variable_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.variable_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_struct_union_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.stuct_union_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_enumerator_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.enumerator_node_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node,
            ctag_entry.pattern,
            comment=comment,
            print_line=print_line,
        )

    def _get_enum_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.enum_node_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_macro_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.macro_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        # also include macros surrounding the target node to assist LLMs
        start_node, end_node = self.macro_finder.get_surrounding_macro_nodes(
            target_node
        )

        snippet = self.generate_snippet_with_nodes(
            start_node, end_node, comment=comment, print_line=print_line
        )

        if snippet is None:
            return None

        if ctag_entry.pattern not in snippet.text:
            return None

        return snippet

    def _get_typedef_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        target_node = self.typedef_finder.get_definition_node(ctag_entry.name)

        if target_node is None:
            return None

        return self._get_snippet_from_node_default(
            target_node, ctag_entry.pattern, comment=comment, print_line=print_line
        )

    def _get_member_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        # @TODO: this type is not used yet. Do we have to consider this type?
        return None

    def _get_header_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        # @TODO: this type is not used yet. Do we have to consider this type?
        return None

    def _get_class_definition(
        self, ctag_entry: CtagEntry, comment: bool = True, print_line: bool = True
    ) -> CodeSnippet | None:
        raise NotImplementedError("implement this function")

    def _get_definition_fail_safe(
        self, ctag_entry: CtagEntry, line_num: int, print_line: bool = True
    ) -> CodeSnippet | None:
        if ctag_entry.kind == TagKind.FUNCTION:
            snippet = self._fail_safe_get_function_definition_heuristic(
                ctag_entry, line_num, print_line=print_line
            )

            if snippet is not None:
                return snippet

        return self._fail_safe_get_surrounding_lines(
            ctag_entry.abs_src_path, line_num, print_line=print_line
        )

    def _fail_safe_get_function_definition_heuristic(
        self, ctag_entry: CtagEntry, line_num: int, print_line: bool = True
    ) -> CodeSnippet | None:
        # @TODO: This functionality will be modified to use ctags-based approach, instead of this heuristic method.
        src_text = ctag_entry.abs_src_path.read_text(encoding="utf-8", errors="ignore")

        lines = [""] + src_text.splitlines(keepends=True)

        for i, line in enumerate(lines[line_num:]):
            if line != FUNCTION_BODY_CLOSING_PATTERN:
                continue

            return get_text_lines_from_file(
                ctag_entry.abs_src_path, line_num, line_num + i, print_line=print_line
            )

        return None

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
            if self.func_finder.has_node(cur_node):
                # @NOTE: tree-sitter seems to wrongly parse functions if complex macros are included in those functions. we will "partially" check this case using `_verify_function_boundary_with_ctags`
                return cur_node
            elif self.class_finder.has_node(cur_node):
                return cur_node
            elif self.variable_finder.has_node(cur_node):
                return cur_node
            elif self.macro_finder.has_node(cur_node):
                return cur_node
            elif self.enum_node_finder.has_node(cur_node):
                return cur_node
            elif self.typedef_finder.has_node(cur_node):
                return cur_node
            elif self.stuct_union_finder.has_node(cur_node):
                return cur_node

            if cur_node.parent is None:
                return None

            cur_node = cur_node.parent

        return None
