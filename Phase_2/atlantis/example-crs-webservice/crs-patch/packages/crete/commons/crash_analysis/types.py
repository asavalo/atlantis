from pathlib import Path
from typing import Callable, TypeAlias

from crete.commons.crash_analysis.models import (
    CrashAnalysisResult,
    CrashStack,
    FunctionFrame,
    InvalidFrame,
)

Frame: TypeAlias = FunctionFrame | InvalidFrame

CrashStacks: TypeAlias = list[CrashStack]

CrashAnalyzer: TypeAlias = Callable[[Path, bytes], CrashAnalysisResult]
