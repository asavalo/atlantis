import os
import subprocess

from python_ripgrep import RIPGREP_EXECUTABLE_FILE

from crete.framework.agent.services.multi_retrieval.nodes.retrievers.base_retriever import (
    BaseRetriever,
)
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalPriority,
    RetrievalQuery,
    RetrievalResult,
)


class RipgrepRetriever(BaseRetriever):
    def __init__(
        self,
        n_context_lines: int = 5,
        max_n_results_per_query: int = 8,
        retrieval_priority: RetrievalPriority = RetrievalPriority.LOW,
    ):
        super().__init__(
            query_category=RetrievalCategory.CODE_SNIPPET,
            max_n_results_per_query=max_n_results_per_query,
        )
        self.n_context_lines = n_context_lines
        self.max_n_results_per_query = max_n_results_per_query
        self.retrieval_priority = retrieval_priority
        if (
            not RIPGREP_EXECUTABLE_FILE.exists()
            or not RIPGREP_EXECUTABLE_FILE.is_file()
        ):
            raise FileNotFoundError(
                f"Ripgrep binary not found at {RIPGREP_EXECUTABLE_FILE}. Please install ripgrep."
            )

    def _retrieve(self, query: RetrievalQuery) -> list[RetrievalResult]:
        if query.query is None or query.query == "":
            return []
        if query.repo_path is None or query.repo_path == "":
            return []

        log = self._run_ripgrep(query.query, query.repo_path)
        if log == "":
            return []

        # TODO: Add support for file_path query. Currently, only repo_path query is handled.

        results: list[RetrievalResult] = []
        for search_result in log.split("\n\n"):
            full_file_path, code = search_result.split("\n", maxsplit=1)
            file_path = os.path.relpath(full_file_path, query.repo_path)
            code_lines = code.split("\n")
            line_start = 0
            for line in code_lines:
                try:
                    line_start = int(line.split(":", maxsplit=1)[0])
                    break
                except ValueError:
                    pass

            line_end = 0
            for line in reversed(code_lines):
                try:
                    line_end = int(line.split(":", maxsplit=1)[0])
                    break
                except ValueError:
                    pass
            result = RetrievalResult(
                content=code,
                file_path=file_path,
                file_lang="",
                line_start=line_start,
                line_end=line_end,
                priority=self.retrieval_priority,
            )
            result.update_from_query(query)
            results.append(result)
        return results

    def _run_ripgrep(self, query: str, repo_path: str) -> str:
        rg_command = [
            RIPGREP_EXECUTABLE_FILE,
            f"--context={self.n_context_lines}",
            "--line-number",
            "--heading",
            "--context-separator=...",
            "--field-context-separator=:",
            "--color=never",
            query,
            repo_path,
        ]
        result = subprocess.run(rg_command, capture_output=True, check=False)
        return result.stdout.decode("utf-8", errors="replace")
