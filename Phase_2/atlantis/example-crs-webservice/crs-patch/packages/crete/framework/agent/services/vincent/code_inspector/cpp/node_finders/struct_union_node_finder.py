from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
    find_child_with_type,
)

DISALLOWD_PARENT_TYPES = [
    "function_definition",
    "parameter_declaration",
    "field_declaration",
    "type_descriptor",
]


def _check_actual_body_exists(node: Node) -> bool:
    if find_child_with_type(node, "field_declaration_list") is None:
        return False
    return True


class StructUnionNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            if self.get_name(node) == target_name:
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type not in ["struct_specifier", "union_specifier"]:
            return False

        if node.parent is None:
            return False

        if node.parent.type in DISALLOWD_PARENT_TYPES:
            return False

        # `struct` and `union` must have a body.
        # That is, it must contain `field_declaration_list` type child.
        if not _check_actual_body_exists(node):
            return False

        return True

    def get_name(self, node: Node) -> str | None:
        type_identifier_node = find_child_with_type(node, "type_identifier")

        if not type_identifier_node:
            return None

        return get_node_text(type_identifier_node)
