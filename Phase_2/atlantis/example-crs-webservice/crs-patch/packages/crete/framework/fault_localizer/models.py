from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class FaultLocation:
    file: Path
    function_name: Optional[str] = None
    # 0-indexed, half-open interval
    line_range: Optional[tuple[int, int]] = None
    description: Optional[str] = None


@dataclass
class FaultLocalizationResult:
    locations: list[FaultLocation]
    description: Optional[str] = None
