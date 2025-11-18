from tree_sitter import Node
from .base_node_finder import BaseNodeFinder


class ClassNodeFinder(BaseNodeFinder):
    def __init__(self):
        super().__init__()

    def get_definition_node(self, target_name: str) -> Node | None:
        raise NotImplementedError("implement this function")

    def is_interesting(self, node: Node) -> bool:
        raise NotImplementedError("implement this function")
