from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class FunctionCall:
    # Caller information
    caller_file: Path  # Relative to the source directory
    caller_name: str
    call_line: int

    # Callee information
    callee_file: Optional[Path]  # Relative to the source directory
    callee_name: str
