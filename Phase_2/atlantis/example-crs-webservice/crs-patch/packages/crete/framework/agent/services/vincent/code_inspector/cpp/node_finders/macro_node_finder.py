from tree_sitter import Node
from .base_node_finder import BaseNodeFinder

from crete.framework.agent.services.vincent.code_inspector.functions import (
    get_node_text,
)


class MacroNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        for node in self._nodes:
            cur_name = self.get_name(node)

            if cur_name and cur_name == target_name:
                return node

        return None

    def is_interesting(self, node: Node) -> bool:
        if node.type == "preproc_def":
            return True
        if node.type == "preproc_function_def":
            return True
        return False

    def get_surrounding_macro_nodes(self, target_node: Node) -> tuple[Node, Node]:
        return (_find_first_macro(target_node), _find_last_macro(target_node))

    def get_name(self, node: Node) -> str | None:
        id_node = node.child_by_field_name("name")

        if id_node is None:
            return None

        return get_node_text(id_node)


def _find_first_macro(node: Node) -> Node:
    cur_node = node
    while cur_node.prev_sibling is not None:
        prev = cur_node.prev_sibling

        if prev.type == "preproc_def":
            cur_node = prev
            continue

        return cur_node

    return cur_node


def _find_last_macro(node: Node) -> Node:
    cur_node = node
    while cur_node.next_sibling is not None:
        prev = cur_node.next_sibling

        if prev.type == "preproc_def":
            cur_node = prev
            continue

        return cur_node

    return cur_node
