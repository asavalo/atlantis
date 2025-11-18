from pathlib import Path

from tree_sitter import Node

from crete.framework.agent.services.vincent.code_inspector.models import CodeSnippet


def get_line_num_with_node(node: Node) -> int:
    return node.start_point[0] + 1


def get_node_text(node: Node) -> str:
    assert node.text is not None
    return node.text.decode("utf-8", errors="replace")


def get_text_lines_from_file(
    src_path: Path, start_line: int, end_line: int, print_line: bool = True
) -> CodeSnippet | None:
    lines = [""] + src_path.read_text(encoding="utf-8", errors="ignore").splitlines(
        keepends=True
    )

    line_cnt = len(lines) - 1
    if line_cnt == 0:  # empty file
        return None

    if start_line <= 0:
        start_line = 1

    if end_line > line_cnt:
        end_line = line_cnt

    code_text = "".join(lines[start_line : end_line + 1])

    if print_line:
        code_text = append_line_num(code_text, start_line)

    return CodeSnippet(start_line=start_line, end_line=end_line, text=code_text)


def append_line_num(snippet: str, start_num: int) -> str:
    """
    append line number starting from `start_num` in front of each code (`snippet`) line
    """
    lines = snippet.splitlines(keepends=True)

    numbered_lines = [f"{start_num + i}:{line}" for i, line in enumerate(lines)]

    return "".join(numbered_lines)


def find_child_with_type(node: Node, type_name: str) -> Node | None:
    for child in node.children:
        if child.type != type_name:
            continue
        return child

    return None


def get_first_comment_node(node: Node) -> Node:
    cur_node = node

    while cur_node is not None:
        prev_node = cur_node.prev_sibling

        if prev_node is None:
            return cur_node

        if prev_node.type not in ["comment", "block_comment"]:
            return cur_node

        cur_node = prev_node

    return cur_node
