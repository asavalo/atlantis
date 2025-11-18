from tree_sitter import Node


class BaseNodeFinder:
    def __init__(self):
        self._nodes: list[Node] = []

    def add_node(self, node: Node):
        self._nodes.append(node)

    def get_definition_node(self, target_name: str) -> Node | None: ...

    def is_interesting(self, node: Node) -> bool: ...

    def has_node(self, node: Node) -> bool:
        if node in self._nodes:
            return True
        return False
