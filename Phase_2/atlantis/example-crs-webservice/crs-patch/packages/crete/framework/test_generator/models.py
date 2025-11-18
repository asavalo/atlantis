from pathlib import Path
from typing import Literal

from pydantic import BaseModel


class TestGenerationResult(BaseModel):
    status: Literal["success", "failure"]
    output: str
    path: Path

    @property
    def script_code(self) -> str:
        return self.path.read_text(errors="replace")
