from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
    find_child_with_type,
)


class FunctionNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            if target_name == self.get_name(node):
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type != "function_definition":
            return False

        if node.parent is None:
            return False

        # @NOTE: tree-sitter treats all of parenthesis '(...)' usages as function definitions.
        # So, filter the cases.
        if node.parent.type == "compound_statement":
            return False

        return True

    def get_name(self, node: Node) -> str | None:
        """
        get function name within the provided `node`.
        @NOTE: tree-sitter has some unknown bugs when it parses C/C++ code...
        """
        func_decl_node = _find_function_declarator_child(node)
        if func_decl_node is not None:
            return _extract_function_name_from_declarator(func_decl_node)

        identifier_node = _find_identifier_child_recursive(node)
        if identifier_node is not None:
            return _filter_out_parenthesis_from_name(get_node_text(identifier_node))

        # @NOTE: tree-sitter-c has some ugly implementation that recognizes function return type as `pointer_declarator` (i.e., use of '*'s), not as `function_declarator`.
        # * Example: Given the function declaration: `static struct tipc_node *tipc_node_find_by_name(...)`,
        #            tree-sitter recognizes a token `*tipc_node_find_by_name` as a pointer, not a function name.
        pointer_decl_node = _find_pointer_declarator_child(node)
        if pointer_decl_node is not None:
            func_name = _extract_func_name_from_pointer_decl_recursive(
                pointer_decl_node
            )
            if func_name is not None:
                return func_name

        return None


def _find_pointer_declarator_child(node: Node) -> Node | None:
    return find_child_with_type(node, "pointer_declarator")


def _find_function_declarator_child(node: Node) -> Node | None:
    return find_child_with_type(node, "function_declarator")


def _extract_func_name_from_pointer_decl_recursive(
    pointer_decl_node: Node,
) -> str | None:
    for child in pointer_decl_node.children:
        if child.type == "function_declarator":
            return _extract_function_name_from_declarator(child)
        if child.type == "pointer_declarator":
            return _extract_func_name_from_pointer_decl_recursive(child)

    return None


def _extract_function_name_from_declarator(node: Node) -> str:
    identifier_node = _find_identifier_child_recursive(node)

    assert identifier_node is not None

    return _filter_out_parenthesis_from_name(get_node_text(identifier_node))


def _filter_out_parenthesis_from_name(name: str) -> str:
    parenthesis_idx = name.find("(")
    if parenthesis_idx == -1:
        return name
    return name[:parenthesis_idx]


def _find_identifier_child_recursive(node: Node) -> Node | None:
    for child in node.children:
        if child.type == "identifier":
            return child

        if child.type == "ERROR":
            return None

        found_identifier = _find_identifier_child_recursive(child)
        if found_identifier is not None:
            return found_identifier

    return None
