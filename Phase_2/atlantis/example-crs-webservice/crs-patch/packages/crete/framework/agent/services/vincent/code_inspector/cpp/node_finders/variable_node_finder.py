from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
)


class VariableNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            if target_name == self.get_name(node):
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type != "declaration":
            return False

        if node.child_by_field_name("type") is None:
            return False

        if node.child_by_field_name("declarator") is None:
            return False

        if node.parent is None:
            return False

        # Ensure the node is not a local variable
        if node.parent.type != "translation_unit":
            return False

        return True

    def get_name(self, node: Node) -> str | None:
        identifier_node = _find_identifier_child_recursive(node)

        if identifier_node is None:
            return None

        return get_node_text(identifier_node)


def _find_identifier_child_recursive(node: Node) -> Node | None:
    for child in node.children:
        if child.type == "identifier":
            return child

        if child.type == "ERROR":
            return None

        found_identifier = _find_identifier_child_recursive(child)
        if found_identifier:
            return found_identifier

    return None
