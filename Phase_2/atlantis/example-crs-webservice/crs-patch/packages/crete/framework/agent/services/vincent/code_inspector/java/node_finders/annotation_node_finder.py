from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
)


class AnnotationNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            found_name = _get_annotation_name_with_node(node)

            if found_name is None:
                continue

            if target_name == found_name:
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type != "annotation_type_declaration":
            return False
        return True


def _get_annotation_name_with_node(node: Node) -> str | None:
    for child in node.children:
        if child.type != "identifier":
            continue

        return get_node_text(child)

    return None
