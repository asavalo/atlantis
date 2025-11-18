from pathlib import Path
from pydantic import BaseModel


class CodeSnippet(BaseModel):
    start_line: int
    end_line: int
    text: str


class CodeQueryResult(BaseModel):
    abs_src_path: Path
    src_path: Path
    snippet: CodeSnippet
    is_tree_sitter: bool
