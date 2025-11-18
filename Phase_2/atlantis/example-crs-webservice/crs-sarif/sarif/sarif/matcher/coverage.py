import json
from pydantic import BaseModel, Field


class FileCoverage(BaseModel):
    src: str
    lines: list[int]


class Coverage(BaseModel):
    files: list[FileCoverage] = Field(
        default=[],
        title="Files",
        description="The list of files with their coverage",
    )

    @classmethod
    def from_coverage_file(cls, coverage_data: str) -> "Coverage":
        coverage = Coverage()
        coverage_data_loaded = json.loads(coverage_data)
        for _, file_coverage in coverage_data_loaded.items():
            coverage_for_function = FileCoverage.model_validate(file_coverage)
            for file in coverage.files:
                if file.src == coverage_for_function.src:
                    file.lines = list(
                        set(file.lines) | set(coverage_for_function.lines)
                    )
                    break
            else:
                coverage.files.append(coverage_for_function)
        return coverage
