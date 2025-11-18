import os
from glob import glob

from crete.framework.agent.services.multi_retrieval.nodes.retrievers.base_retriever import (
    BaseRetriever,
)
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalPriority,
    RetrievalQuery,
    RetrievalResult,
)


class FileRetriever(BaseRetriever):
    def __init__(
        self,
        add_line_numbers: bool = False,
        encoding: str = "utf-8",
        max_n_results_per_query: int = 8,
        retrieval_priority: RetrievalPriority = RetrievalPriority.LOW,
    ):
        super().__init__(
            query_category=RetrievalCategory.FILE,
            max_n_results_per_query=max_n_results_per_query,
        )
        self.add_line_numbers = add_line_numbers
        self.encoding = encoding
        self.retrieval_priority = retrieval_priority

    def _retrieve(self, query: RetrievalQuery) -> list[RetrievalResult]:
        if query.query is None or query.query == "":
            return []
        if query.repo_path is None or query.repo_path == "":
            return []
        if query.category != RetrievalCategory.FILE:
            return []
        original_query = query.query
        query.query, line_start, line_end = self._extract_line_ranges(query.query)

        rebased_file_path = self._rebase_file_path(query.query, query.repo_path)
        if rebased_file_path is not None:
            full_file_path = os.path.join(query.repo_path, rebased_file_path)
            if not os.path.exists(full_file_path) or not os.path.isfile(full_file_path):
                return []

            file_src, line_start, line_end = self._get_file_content(
                full_file_path, line_start, line_end
            )
            result = RetrievalResult(
                content=file_src,
                file_lang="",
                file_path=rebased_file_path,
                line_start=line_start,
                line_end=line_end,
                priority=self.retrieval_priority,
            )
            query.query = original_query
            result.update_from_query(query)
            if self.add_line_numbers:
                result.add_line_numbers()
            return [result]

        searched_files = self._search_file_path_with_name(query.query, query.repo_path)
        if len(searched_files) == 0:
            return []

        results: list[RetrievalResult] = []
        for file_path in searched_files:
            full_file_path = os.path.join(query.repo_path, file_path)
            if not os.path.exists(full_file_path) or not os.path.isfile(full_file_path):
                continue
            file_src, line_start, line_end = self._get_file_content(
                full_file_path, line_start, line_end
            )
            result = RetrievalResult(
                content=file_src,
                file_lang="",
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                priority=self.retrieval_priority,
            )
            query.query = original_query
            result.update_from_query(query)
            if self.add_line_numbers:
                result.add_line_numbers()
            results.append(result)
        return results

    def _rebase_file_path(self, query: str, repo_path: str) -> str | None:
        # This searches a file where repo_path and issue log's file path have different base paths.
        query_paths = query.split(os.path.sep)
        rebased_file_path = None
        for i in range(len(query_paths)):
            curr_path = os.path.join(*query_paths[i:])
            check_path = os.path.join(repo_path, curr_path)
            if os.path.exists(check_path) and os.path.isfile(check_path):
                rebased_file_path = curr_path
                break
        return rebased_file_path

    def _get_file_content(
        self, file_path: str, line_start: int | None, line_end: int | None
    ) -> tuple[str, int, int]:
        with open(file_path, "r", encoding=self.encoding, errors="replace") as f:
            file_src = f.read()
        src_lines = file_src.split("\n")
        if src_lines[-1] == "":
            src_lines.pop()

        if line_start is None or line_end is None:
            return file_src, 1, len(src_lines)

        if line_start < 1:
            line_start = 1
        if line_start > len(src_lines):
            line_start = len(src_lines)
        if line_end < 1:
            line_end = 1
        if line_end > len(src_lines):
            line_end = len(src_lines)

        file_src = "".join(
            [f"{line}\n" for line in src_lines[line_start - 1 : line_end]]
        )
        return file_src, line_start, line_end

    def _search_file_path_with_name(self, query: str, repo_path: str) -> list[str]:
        searched_files = glob(
            os.path.join("**", os.path.split(query)[-1]),
            root_dir=repo_path,
            recursive=True,
        )
        return searched_files

    def _extract_line_ranges(self, query: str) -> tuple[str, int | None, int | None]:
        if ":" not in query:
            return query, None, None
        file_path, line_range = query.split(":")
        if "-" not in line_range:
            try:
                line_range = line_range.strip()
                line_start = int(line_range)
                line_end = int(line_range)
                return file_path, line_start, line_end
            except ValueError:
                return file_path, None, None
        line_start, line_end = line_range.split("-")
        try:
            line_start = int(line_start.strip())
            line_end = int(line_end.strip())
        except ValueError:
            return file_path, None, None
        return file_path, line_start, line_end
