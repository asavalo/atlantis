import re
from typing import AnyStr, TypeVar

T = TypeVar("T")


def remove_ansi_escape_codes(data: AnyStr) -> AnyStr:
    if isinstance(data, str):
        return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", data)
    else:
        return re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", data)


def not_none(x: T | None) -> T:
    assert x is not None
    return x


def add_line_numbers(code_snippet: str, start_line: int) -> str:
    """
    Prefixes each line of the given code snippet with a line number.

    Args:
        code_snippet (str): The code snippet as a multiline string.
        start_line (int): The starting line number to prefix. Defaults to 1.

    Returns:
        str: The code snippet with each line prefixed by its corresponding line number.

    Example:
        code = "a = 1\\nb = 2"
        add_line_numbers(code, start_line=10)
        # Output:
        #     10: a = 1
        #     11: b = 2

    Line numbers are right-justified with width 6.
    """
    lines = code_snippet.split("\n")
    numbered_lines = [
        f"{str(start_line + i).rjust(6)}: {line}" for i, line in enumerate(lines)
    ]
    return "\n".join(numbered_lines)
