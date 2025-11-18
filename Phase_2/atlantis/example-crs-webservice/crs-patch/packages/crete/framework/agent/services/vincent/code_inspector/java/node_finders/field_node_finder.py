from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
)


class FieldNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            # @TODO: refactor this logic
            if target_name in get_node_text(node):
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type != "field_declaration":
            return False
        return True
