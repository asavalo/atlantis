from collections import Counter
from pathlib import Path
from typing import List, Literal

from crete.atoms.report import CreteResult, DiffResult, ErrorResult, NoPatchResult
from pydantic import BaseModel
from pygit2 import Repository

ResultVariant = Literal[
    "sound",
    "vulnerable",
    "compilable",
    "uncompilable",
    "wrong",
    "wrong_format",
    "internal_tests_failure",
    "unknown_error",
    "no_patch",
]

RESULT_VARIANT_ORDER: List[ResultVariant] = [
    "sound",
    "vulnerable",
    "internal_tests_failure",
    "compilable",
    "uncompilable",
    "wrong",
    "no_patch",
    "unknown_error",
    "wrong_format",
]


class BenchmarkResult(BaseModel):
    cpv_name: str
    variant: ResultVariant
    elapsed_time: int = 0
    llm_cost: float = 0
    message: str = ""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, BenchmarkResult) and self.cpv_name == other.cpv_name

    def is_worse_than(self, other: "BenchmarkResult") -> bool:
        assert self.variant in RESULT_VARIANT_ORDER
        assert other.variant in RESULT_VARIANT_ORDER
        return RESULT_VARIANT_ORDER.index(self.variant) > RESULT_VARIANT_ORDER.index(
            other.variant
        )

    def save(self, path: Path):
        path.write_text(self.model_dump_json())

    @staticmethod
    def load(path: Path) -> "BenchmarkResult":
        return BenchmarkResult.model_validate_json(path.read_text())

    @staticmethod
    def from_crete_result(
        result: CreteResult, cpv_name: str, elapsed_time: int, llm_cost: float
    ) -> "BenchmarkResult":
        match result:
            case DiffResult(variant=variant) | NoPatchResult(variant=variant):
                return BenchmarkResult.model_validate(
                    {
                        "cpv_name": cpv_name,
                        "variant": variant,
                        "elapsed_time": elapsed_time,
                        "llm_cost": llm_cost,
                    }
                )
            case ErrorResult(variant=variant, error=error):
                return BenchmarkResult.model_validate(
                    {
                        "cpv_name": cpv_name,
                        "variant": variant,
                        "message": str(error),
                        "elapsed_time": elapsed_time,
                        "llm_cost": llm_cost,
                    }
                )


class BenchmarkReport(BaseModel):
    app: str
    commit_hash: str
    commit_timestamp: int
    statistics: List[tuple[ResultVariant, int]]
    total_elapsed_time: int
    total_llm_cost: float
    results: List[BenchmarkResult]

    @staticmethod
    def from_benchmark_results(
        app_id: str, results: List[BenchmarkResult]
    ) -> "BenchmarkReport":
        repository = Repository(".")  # FIXME: This is a hardcoded path
        head_commit = repository[repository.head.target].peel(1)

        return BenchmarkReport.model_validate(
            {
                "app": app_id,
                "commit_hash": str(head_commit.id),
                "commit_timestamp": head_commit.commit_time,
                "statistics": list(
                    Counter(result.variant for result in results).items()
                ),
                "results": results,
                "total_elapsed_time": sum(result.elapsed_time for result in results),
                "total_llm_cost": sum(result.llm_cost for result in results),
            }
        )

    def save(self, report_path: Path):
        report_path.write_text(self.model_dump_json(indent=2))

    def append(self, report_path: Path):
        existing_report = BenchmarkReport.load(report_path)

        assert self.app == existing_report.app
        assert self.commit_hash == existing_report.commit_hash
        assert self.commit_timestamp == existing_report.commit_timestamp

        results = existing_report.results + self.results
        results = list({result.cpv_name: result for result in results}.values())

        BenchmarkReport.model_validate(
            {
                "app": existing_report.app,
                "commit_hash": existing_report.commit_hash,
                "commit_timestamp": existing_report.commit_timestamp,
                "statistics": list(
                    Counter(result.variant for result in results).items()
                ),
                "results": results,
                "total_elapsed_time": sum(result.elapsed_time for result in results),
                "total_llm_cost": sum(result.llm_cost for result in results),
            }
        ).save(report_path)

    @staticmethod
    def load(report_path: Path) -> "BenchmarkReport":
        return BenchmarkReport.model_validate_json(report_path.read_text())
