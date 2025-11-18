#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Dict, Set, Tuple

import cbor2
import os
import tempfile
from pydantic import BaseModel, ValidationError
from collections import deque

# ────────────────────────────  pydantic schemas  ──────────────────────────────


class InputByte(BaseModel):
    offset: int
    value: int


class DataLength(BaseModel):
    value: int


class Extract(BaseModel):
    op: int
    first_bit: int
    last_bit: int


class Concat(BaseModel):
    a: int
    b: int


class SymbolicComputationOutput(BaseModel):
    output: int
    label: str


class SymbolicComputationInput(BaseModel):
    index: int
    input: int
    is_symbolic: bool


class ReadMemory(BaseModel):
    address: int
    size: int
    output: int


class WriteMemory(BaseModel):
    address: int
    size: int
    input: int


class PathConstraint(BaseModel):
    constraint: int
    taken: bool
    location: int


# ─────────────────────────────  tree structure  ───────────────────────────────


class Node:
    expr_id: int
    label: Optional[str] = None

    def __init__(self, label: Optional[str] = None):
        self.label = label
        self.tag = id(self)

    def title(self) -> str:
        raise NotImplementedError("title() must be implemented in subclasses")

    def __hash__(self) -> int:
        return hash(self.tag)


class SymbolicValueNode(Node):
    def __init__(self, expr_id: int, is_symbolic: bool, label: Optional[str] = None):
        super().__init__(label)
        self.is_symbolic = is_symbolic
        self.expr_id = expr_id
        self.path_constraint = False

    def title(self) -> str:
        return f"{self.expr_id}"

    def declare_path_constraint(self, site_id: int) -> None:
        self.path_constraint = True
        self.site_id = site_id

    def __hash__(self) -> int:
        return super().__hash__()


class InvalidSymbolicValueNode(Node):
    def __init__(self, label: Optional[str] = None):
        super().__init__(label)
        self.is_symbolic = False
        self.label = label

    def title(self) -> str:
        return f"INVALID"

    def __hash__(self) -> int:
        return super().__hash__()


class MemoryNode(Node):
    def __init__(
        self,
        address: int,
        label: Optional[str] = None,
    ):
        super().__init__(label)
        self.address = address

    def title(self) -> str:
        return f"MEM"

    def __hash__(self) -> int:
        return super().__hash__()


class Edge:
    def __init__(self, parent: Node, child: Node):
        self.parent = parent
        self.child = child

    def __hash__(self) -> int:
        return hash((self.parent, self.child))


INVALID_ID = 0x1337_1337


class Tree:
    def __init__(self):
        self.roots: List[int] = []
        self.nodes: Set[Node] = set()
        self.symbolic_value_nodes: Dict[int, SymbolicValueNode] = {}
        self.edges: List[Edge] = []

    def add_node(self, node: Node, overwrite_ok: bool = False) -> None:
        if (
            (not overwrite_ok)
            and isinstance(node, SymbolicValueNode)
            and node.expr_id != INVALID_ID
        ):
            assert (
                not node.expr_id in self.symbolic_value_nodes
            ), f"Node {node.expr_id} already exists in the tree"
            self.symbolic_value_nodes[node.expr_id] = node
        self.nodes.add(node)

    def add_edge(self, parent: Node, child: Node) -> None:
        self.edges.append(Edge(parent, child))

    def symbolic_value_exists(self, expr_id: int) -> bool:
        return expr_id in self.symbolic_value_nodes

    def dump_dot(self) -> str:
        out = ""
        out += "digraph SymbolicTree {\n"
        out += "  rankdir=TB;\n"
        out += "  ordering=out;\n"
        out += '  node [shape=circle, style=filled, fillcolor=lightblue, fontname="monospace"];\n\n'

        nodes = set()
        edges = set()
        for node in self.nodes:
            if isinstance(node, SymbolicValueNode) and node.path_constraint:
                nodes_, edges_ = self.dfs(node)
                nodes.update(nodes_)
                edges.update(edges_)
        for node in nodes:
            penwidth = 1
            if isinstance(node, SymbolicValueNode):
                if node.is_symbolic:
                    color = "red"
                    if node.path_constraint:
                        penwidth = 4
                else:
                    color = "lightgray"
            elif isinstance(node, MemoryNode):
                color = "lightgreen"
            else:
                color = "lightgray"
            out += f'  {node.tag} [label="{node.title()}", fillcolor={color}, penwidth={penwidth:.2f}];\n'
        for edge in edges:
            out += f"  {edge.parent.tag} -> {edge.child.tag}\n"

        out += "}\n"
        return out

    def dfs(self, node: Node) -> Tuple[List[Node], List[Edge]]:
        stack = [node]
        nodes = []
        edges = []
        while stack:
            current = stack.pop()
            nodes.append(current)
            for edge in self.edges:
                if edge.parent.tag == current.tag:
                    stack.append(edge.child)
                    edges.append(edge)
        return nodes, edges

    def topo_sort(self) -> List[Node]:
        indegree = {node: 0 for node in self.nodes}
        adj = {node: [] for node in self.nodes}
        for edge in self.edges:
            p = edge.parent
            c = edge.child
            indegree[c] += 1
            adj[p].append(c)

        queue = deque(node for node, d in indegree.items() if d == 0)
        order = []

        while queue:
            node = queue.popleft()
            order.append(node)
            for child in adj[node]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)

        return order


NON_EXPR_ITEMS = [
    "Call",
    "Return",
    "BasicBlock",
    "Function",
    "ReadMemory",
    "WriteMemory",
    "SymbolicComputationInput",
    "SymbolicComputationOutput",
]


def build_tree(events) -> Tree:
    tree = Tree()
    current_children: List[Node] = []
    memory_nodes: Dict[int, MemoryNode] = {}
    exprs = {}
    for sym_expr_id, payload in events:
        keys = [x for x in payload.keys()]
        if len(keys) != 1:
            raise ValueError(f"Invalid payload: {payload}")
        key = keys[0]
        if not (key in NON_EXPR_ITEMS):
            exprs[sym_expr_id] = payload
        if key == "InputByte":
            inp = InputByte(**payload[key])
            node = SymbolicValueNode(
                sym_expr_id, True, label=f"InputByte({inp.offset:x})"
            )
            tree.add_node(node)

        elif key == "DataLength":
            data_length = DataLength(**payload[key])
            node = SymbolicValueNode(
                sym_expr_id, True, label=f"DataLength({data_length.value})"
            )
            tree.add_node(node)
        elif key == "Concat":
            concat = Concat(**payload[key])
            node_src = SymbolicValueNode(
                sym_expr_id, True, label=f"Concat({concat.a:x}, {concat.b:x})"
            )
            if tree.symbolic_value_exists(concat.a):
                node_a = tree.symbolic_value_nodes[concat.a]
            else:
                node_a = SymbolicValueNode(concat.a, False, label=f"unknown")
            if tree.symbolic_value_exists(concat.b):
                node_b = tree.symbolic_value_nodes[concat.b]
            else:
                node_b = SymbolicValueNode(concat.b, False, label=f"unknown")
            tree.add_node(node_src)
            tree.add_edge(node_src, node_a)
            tree.add_edge(node_src, node_b)
        elif key == "Extract":
            extract = Extract(**payload[key])
            node_src = SymbolicValueNode(
                sym_expr_id, False, label=f"Extract({extract.op:x})"
            )
            tree.add_node(node_src)
            if tree.symbolic_value_exists(extract.op):
                node_dst = tree.symbolic_value_nodes[extract.op]
            else:
                node_dst = SymbolicValueNode(extract.op, False, label=f"unknown")
            tree.add_edge(node_src, node_dst)
        elif key == "SymbolicComputationOutput":
            out = SymbolicComputationOutput(**payload[key])
            if out.output == INVALID_ID:
                continue
            if out.output in tree.symbolic_value_nodes:
                node_src = tree.symbolic_value_nodes[out.output]
            else:
                is_symbolic = (
                    sum(
                        [
                            1 if child.is_symbolic else 0
                            for child in current_children
                            if isinstance(child, SymbolicValueNode)
                        ]
                    )
                    > 0
                )
                node_src = SymbolicValueNode(
                    out.output, is_symbolic, label=out.label
                )
                tree.add_node(node_src)
            for child in current_children:
                tree.add_edge(node_src, child)
            current_children = []
        elif key == "SymbolicComputationInput":
            inp = SymbolicComputationInput(**payload[key])
            if tree.symbolic_value_exists(inp.input):
                node_src = tree.symbolic_value_nodes[inp.input]
                node_src.is_symbolic = inp.is_symbolic
            else:
                node_src = SymbolicValueNode(inp.input, inp.is_symbolic)
                tree.add_node(node_src)
            current_children.append(node_src)
        elif key == "PathConstraint":
            pc = PathConstraint(**payload[key])
            if not pc.constraint in tree.symbolic_value_nodes:
                node_src = SymbolicValueNode(pc.constraint, False)
                node_src.declare_path_constraint(pc.location)
                tree.add_node(node_src)
            else:
                node_src = tree.symbolic_value_nodes[pc.constraint]
                node_src.declare_path_constraint(pc.location)
        elif key == "ReadMemory":
            read = ReadMemory(**payload[key])
            if read.address in memory_nodes:
                """
                For the case of 1 byte reads, no concat happens, so the expression may not exist in the tree yet.
                """
                if read.size == 1:
                    assert (
                        tree.symbolic_value_exists(read.output) is False
                    ), f"Node {read.output} already exists in the tree"
                    node_src = SymbolicValueNode(
                        read.output,
                        read.output != INVALID_ID,
                        label=f"ReadMemory({read.address:x})",
                    )
                    tree.add_node(node_src)
                for i in range(read.size):
                    address = read.address + i
                    node_dst = memory_nodes[address]
                    if read.output == INVALID_ID:
                        node_src = InvalidSymbolicValueNode()
                    else:
                        assert tree.symbolic_value_exists(read.output)
                        node_src = tree.symbolic_value_nodes[read.output]
                    tree.add_edge(node_src, node_dst)
        elif key == "WriteMemory":
            write = WriteMemory(**payload[key])
            for i in range(write.size):
                address = write.address + i
                node_src = MemoryNode(address)
                memory_nodes[address] = node_src
                tree.add_node(node_src)
                if tree.symbolic_value_exists(write.input):
                    node_dst = tree.symbolic_value_nodes[write.input]
                else:
                    """
                    It is possible for the input to not be a symbolic computation output:
                    1. The input has an INVAID_ID, meaining that it is concrete.
                    2. The input is the result of _sym_concat_helper inside the runtime
                    """
                    node_dst = SymbolicValueNode(write.input, write.input != INVALID_ID)
                    tree.add_node(node_dst)
                tree.add_edge(node_src, node_dst)
    assert len(current_children) == 0, "Unfinished computation tree"
    return tree


def main() -> None:
    ap = argparse.ArgumentParser(description="Build a symbolic computation tree")
    ap.add_argument("input_file", type=Path, help="CBOR file with event list")
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("output.png"),
        help="write result to file",
    )
    args = ap.parse_args()

    events = cbor2.load(args.input_file.open("rb"))
    if not isinstance(events, list):
        raise ValueError("Top-level CBOR object must be a list")

    tree = build_tree(events)
    dot_string = tree.dump_dot()
    with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as tmp:
        tmp.write(dot_string.encode("utf-8"))
        tmp_name = tmp.name
    os.system(f"dot -Tpng {tmp_name} -o {args.output}")


if __name__ == "__main__":
    main()
