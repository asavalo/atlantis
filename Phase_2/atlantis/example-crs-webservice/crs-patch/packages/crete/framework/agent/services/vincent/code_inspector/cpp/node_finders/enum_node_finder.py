from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
    find_child_with_type,
)


class EnumNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            if self.get_name(node) == target_name:
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type != "enum_specifier":
            return False
        return True

    def get_name(self, node: Node) -> str | None:
        type_identifier_node = find_child_with_type(node, "type_identifier")

        if type_identifier_node is None:
            return None

        return get_node_text(type_identifier_node)
