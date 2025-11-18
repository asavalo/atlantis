from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
    find_child_with_type,
)


def _check_node_contains_enumumerator_name(node: Node, target_name: str) -> bool:
    enum_list_node = find_child_with_type(node, "enumerator_list")

    if enum_list_node is None:
        return False

    for child in enum_list_node.children:
        enumerator_node = find_child_with_type(child, "enumerator")

        if enumerator_node is None:
            continue

        name_node = enumerator_node.child_by_field_name("name")
        if name_node is None:
            continue

        if get_node_text(name_node) == target_name:
            return True

    return False


class EnumeratorNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            if _check_node_contains_enumumerator_name(node, target_name):
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type != "enum_specifier":
            return False
        return True
