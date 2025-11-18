import importlib.resources as resources
from abc import ABC
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from sarif.tools.codeql.queries import sink_analysis_c, sink_analysis_java

# CWE-415: Double Free
# CWE-416: Use After Free
# CWE-122: Heap Buffer Overflow
# CWE-121: Stack Buffer Overflow
# CWE-121: Global Buffer Overflow
# CWE-562: Return of Stacked Local Values
# CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
# CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
# CWE-120: Buffer Copy without Checking Size of Input
# CWE-20: Improper Input Validation
# CWE-125: Out-of-bounds Read
# CWE-787: Out-of-bounds Write

# ASan detectable
# Out-of-bounds accesses to heap, stack and globals
# Use-after-free
# Use-after-return (clang flag -fsanitize-address-use-after-return=(never|runtime|always) default: runtime)
# Use-after-scope (clang flag -fsanitize-address-use-after-scope)
# Double-free, invalid free

# UBSan detectable
# Array subscript out of bounds, where the bounds can be statically determined
# Bitwise shifts that are out of bounds for their data type
# Dereferencing misaligned or null pointers
# Signed integer overflow
# Conversion to, from, or between floating-point types which would overflow the destination


class SinkLocation(BaseModel):
    func_name: str = Field(default="")
    file_name: str = Field(default="")
    line_start: int = Field(default=1)
    column_start: int = Field(default=1)
    line_end: int = Field(default=1)
    column_end: int = Field(default=1)
    location: str = Field(default="")
    sink_func_name: str = Field(default="")


class DataAugmentation(ABC):
    def __init__(
        self,
        # src_dir: Path,
        db_path: Path,
        lang: Literal["c", "cpp", "java"],
        cwe_id: str,  # e.g., "cwe-123"
    ):
        # self.src_dir = src_dir
        self.db_path = db_path
        self.lang = lang
        self.cwe_id = cwe_id

        self.sink_candidate_csv = Path(f"sarif/sarif/codeql/data/sinks_{lang}.csv")

    def _get_candidate_csv_path(self) -> Path:
        with resources.path(
            f"sarif.static.sinks.{self.lang}", self.cwe_id + ".csv"
        ) as path:
            print(path)
            return path

    def _get_sink_candidates(self) -> list[SinkLocation]:
        if self.lang == "c" or self.lang == "cpp":
            query = sink_analysis_c
        elif self.lang == "java":
            query = sink_analysis_java

        res = query.run(
            database=self.db_path,
            external={
                "sink_candidates": self._get_candidate_csv_path().as_posix(),
            },
        )

        run_res = res.parse()

        sink_candidates = []
        for row in run_res:
            sink_candidates.append(
                SinkLocation(
                    func_name=row["func_name"],
                    file_name=row["func_file_name"],
                    line_start=row["line_start"],
                    column_start=row["column_start"],
                    line_end=row["line_end"],
                    column_end=row["column_end"],
                    location=row["location"],
                    sink_func_name=row["sink_func_name"],
                )
            )

        return sink_candidates
