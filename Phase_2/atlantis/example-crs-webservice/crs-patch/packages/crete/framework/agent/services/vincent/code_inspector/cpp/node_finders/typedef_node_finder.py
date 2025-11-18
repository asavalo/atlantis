from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
)


class TypedefNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            if self.get_name(node) == target_name:
                # To extract the full code of typedef,
                # use the parent node of the current node.
                return node.parent

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.parent is None:
            return False

        if node.type != "type_identifier":
            return False

        if node.parent.type != "type_definition":
            return False

        return True

    def get_name(self, node: Node) -> str | None:
        return get_node_text(node)
