from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class LLMCommitAnalysis:
    vulnerability_type: str
    severity: float
    description: str
    error: str | None = None
    raw_response: str | None = None
    recommendation: str | None = None
    problematic_lines: List[str] | None = None
    patches_to_avoid: List[str] | None = None


@dataclass
class PatchInfo:
    file_path: str = ""
    function_name: str = ""
    commit_hash: str = ""
    diff_content: str = ""
    header: str = ""

    def __str__(self) -> str:
        return f"\n\n{self.header}\n{self.diff_content}"


@dataclass
class FunctionDiffInfo:
    file_path: str
    original_line_span: Tuple[int, int]
    new_line_span: Tuple[int, int]
    diff: str
