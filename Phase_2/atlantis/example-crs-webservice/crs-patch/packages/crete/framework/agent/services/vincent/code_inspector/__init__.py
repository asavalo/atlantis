import os
from pathlib import Path
from tree_sitter import Parser
from tree_sitter_language_pack import get_language
from crete.framework.language_parser.services.ctags import (
    CtagsParser,
    CtagEntry,
    TagKind,
)
from python_aixcc_challenge.language.types import Language
from crete.framework.agent.services.vincent.code_inspector.models import (
    CodeQueryResult,
    CodeSnippet,
)
from crete.framework.code_inspector.functions import search_string_in_source_directory
from crete.framework.agent.services.vincent.code_inspector.cpp import CppInspector
from crete.framework.agent.services.vincent.code_inspector.java import JavaInspector
from crete.framework.agent.services.vincent.code_inspector.functions import (
    append_line_num,
)

# @TODO: devise more reasonable way to identify source files instead of using file extensions.
ALLOWED_EXTENSIONS = [
    ".c",
    ".cc",
    ".cxx",
    ".c++",
    ".C",
    ".cpp",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".h++",
    ".H",
    ".java",
    ".tcc",
    ".inl",
    ".inc",
    ".in",
]

MIDDLE_LINE_NUM_ADDITION_CNT = 3


class VincentCodeInspector:
    def __init__(self, proj_path: Path, cache_dir: Path, lang: Language):
        self.proj_path = proj_path
        self.cache_dir = cache_dir
        self.lang: Language = lang
        self.inspectors: dict[Path, CppInspector | JavaInspector] = {}
        self.snippet_hashes: set[int] = set()

        if not self.proj_path.exists():
            raise FileNotFoundError(f"Project path '{self.proj_path}' not found")

        if not os.path.exists(self.cache_dir):
            os.mkdir(self.cache_dir)

        self.ctags_parser = CtagsParser(self.proj_path, self.cache_dir / "tags", lang)

        self.parser = Parser()
        match self.lang:
            case "c" | "cpp" | "c++":
                self.parser.language = get_language("c")
            case "jvm":
                self.parser.language = get_language("java")

    def _get_inspector(self, src_path: Path) -> CppInspector | JavaInspector:
        if src_path in self.inspectors.keys():
            return self.inspectors[src_path]

        match self.lang:
            case "c" | "cpp" | "c++":
                inspector = CppInspector(src_path, self.proj_path, self.parser)
            case "jvm":
                inspector = JavaInspector(src_path, self.proj_path, self.parser)

        self.inspectors[src_path] = inspector

        return inspector

    def get_definition(
        self, target_name: str, print_line: bool = True
    ) -> list[CodeQueryResult] | None:
        """
        get the code snippets that defines `name` in the given project.
        """
        entries = self.ctags_parser.get_tag_entries_by_name(target_name)

        if len(entries) == 0:
            # `name` not found in ctags database.
            return None

        results: list[CodeQueryResult] = []

        if self.lang == "jvm":
            entries = _remove_constructor_method(entries)

        for entry in entries:
            if entry.abs_src_path.suffix not in ALLOWED_EXTENSIONS:
                continue

            inspector = self._get_inspector(entry.abs_src_path)
            query_result = inspector.get_definition(entry, print_line)

            if query_result is None:
                continue

            if not self._verify_query_result_using_function_boundary(query_result):
                query_result = self._trim_code_query_result_using_function(query_result)
                if query_result is None:
                    continue

            self.snippet_hashes.add(hash(query_result.snippet.text))

            results.append(query_result)

        if len(results) == 0:
            return None

        # return extracted snippets
        return results

    def get_definition_likely_lines(
        self, src_path: Path, target_name: str
    ) -> list[tuple[int, int]] | None:
        assert src_path.is_absolute()

        if self.lang == "jvm":
            return None

        definition_likely_lines = self._get_inspector(
            src_path
        ).get_definition_likely_lines(target_name)

        if len(definition_likely_lines) == 0:
            return None

        return definition_likely_lines

    def get_references(
        self, name: str, print_line: bool = True
    ) -> list[CodeQueryResult] | None:
        grep_results = search_string_in_source_directory(
            self.proj_path, name, log_output=False
        )

        if len(grep_results) == 0:
            return None

        results: list[CodeQueryResult] = []
        for src_path, line_num, _ in grep_results:
            if src_path.suffix not in ALLOWED_EXTENSIONS:
                continue

            # Fix line number to start from 1, instead of 0
            line_num = line_num + 1

            target_entry = self.ctags_parser.get_entry_at_line(src_path, line_num)
            if target_entry is None:
                continue

            # To prevent excessive token usage, restrict the references from function or method.
            if target_entry.kind not in [TagKind.FUNCTION, TagKind.METHOD]:
                continue

            if target_entry.line == line_num:
                # It means it's a definition
                continue

            snippet = self._get_snippet_with_tag_entry(
                target_entry, print_line=print_line
            )

            query_result = CodeQueryResult(
                abs_src_path=target_entry.abs_src_path,
                src_path=target_entry.rel_src_path,
                snippet=snippet,
                is_tree_sitter=False,
            )

            # Unlike `get_definition`, `get_references` will not output the result if it has history to avoid excessive token usage.
            snippet_hash = hash(query_result.snippet.text)
            if snippet_hash in self.snippet_hashes:
                continue

            self.snippet_hashes.add(snippet_hash)

            results.append(query_result)

        if len(results) == 0:
            return None

        return results

    def _get_snippet_with_tag_entry(
        self, target_entry: CtagEntry, print_line: bool = True
    ) -> CodeSnippet:
        lines = [""] + target_entry.abs_src_path.read_text(
            encoding="utf-8", errors="ignore"
        ).splitlines(keepends=True)

        start_line = target_entry.line

        while start_line > 1:
            if lines[start_line] == "\n":  # it's an empty line
                start_line = start_line + 1
                break
            start_line -= 1

        entry_after_target = self.ctags_parser.get_entry_after_line(
            target_entry.abs_src_path, target_entry.line + 1
        )

        if entry_after_target is None:
            end_line = len(lines) - 1
        else:
            end_line = entry_after_target.line - 1

        snippet_text = "".join(lines[start_line : end_line + 1])
        if print_line:
            snippet_text = append_line_num(snippet_text, start_line)

        return CodeSnippet(start_line=start_line, end_line=end_line, text=snippet_text)

    def _trim_code_query_result_using_function(
        self, query_result: CodeQueryResult
    ) -> CodeQueryResult | None:
        next_func_entry = self.ctags_parser.get_entry_after_line(
            query_result.abs_src_path,
            _get_middle_line_num(query_result.snippet),
            entry_kind=TagKind.FUNCTION,
        )

        if next_func_entry is None:
            return query_result

        new_end_line = next_func_entry.line - 1

        if query_result.snippet.start_line > new_end_line:
            return None

        if query_result.snippet.end_line < new_end_line:
            return None

        # make new query_result with a trimmed snippet
        return CodeQueryResult(
            abs_src_path=query_result.abs_src_path,
            src_path=query_result.src_path,
            snippet=_trim_code_snippet(
                query_result.snippet,
                new_end_line,
            ),
            is_tree_sitter=False,
        )

    def get_visited_src_list(self) -> list[Path]:
        return list(self.inspectors.keys())

    def get_all_functions_in_source(self, src_path: Path) -> list[CtagEntry]:
        result: list[CtagEntry] = []
        for entry in self.ctags_parser.get_all_functions():
            if entry.abs_src_path != src_path:
                continue
            result.append(entry)
        return result

    def _verify_query_result_using_function_boundary(
        self, query_result: CodeQueryResult
    ) -> bool:
        if not query_result.is_tree_sitter:
            # It's already a fail-safe'ed snippet
            return True

        entry_before_start_line = self.ctags_parser.get_entry_before_line(
            query_result.abs_src_path,
            _get_middle_line_num(query_result.snippet),
            entry_kind=TagKind.FUNCTION,
        )

        if entry_before_start_line is None:
            return True

        entry_before_end_line = self.ctags_parser.get_entry_before_line(
            query_result.abs_src_path,
            query_result.snippet.end_line,
            entry_kind=TagKind.FUNCTION,
        )

        return entry_before_start_line == entry_before_end_line


def _trim_code_snippet(snippet: CodeSnippet, new_end_line: int) -> CodeSnippet:
    assert snippet.start_line < new_end_line, (
        f"original start_line {snippet.start_line} is larger than new end_line {new_end_line}"
    )
    assert snippet.end_line > new_end_line, (
        f"original end_line {snippet.end_line} is larger than new {new_end_line}"
    )

    lines = snippet.text.splitlines(keepends=True)
    line_cnt = new_end_line - snippet.start_line + 1

    return CodeSnippet(
        start_line=snippet.start_line,
        end_line=new_end_line,
        text="".join(lines[:line_cnt]),
    )


# @NOTE: The actual starting point and ctags entry's line number is slightly different.
# 2045:void     //  <= actual starting point of the function
# 2046:ngx_http_process_request(ngx_http_request_t *r) // But, ctags points here...
# 2047:{
# 2048:    ngx_connection_t  *c;
# 2049:
# 2050:    c = r->connection;
def _get_middle_line_num(snippet: CodeSnippet) -> int:
    if snippet.start_line == snippet.end_line:
        return snippet.start_line

    if snippet.end_line - snippet.start_line > MIDDLE_LINE_NUM_ADDITION_CNT:
        return snippet.start_line + MIDDLE_LINE_NUM_ADDITION_CNT

    return snippet.start_line + 1


def _remove_constructor_method(entries: list[CtagEntry]) -> list[CtagEntry]:
    result: list[CtagEntry] = []
    method_entries: list[CtagEntry] = []
    class_entries: list[CtagEntry] = []

    for entry in entries:
        if entry.kind == TagKind.CLASS:
            class_entries.append(entry)
        elif entry.kind == TagKind.METHOD:
            method_entries.append(entry)
        else:
            result.append(entry)

    valid_method_entry: list[CtagEntry] = []
    for method_entry in method_entries:
        same = False
        for class_entry in class_entries:
            if method_entry.name != class_entry.name:
                continue
            same = True
            break

        if not same:
            valid_method_entry.append(method_entry)

    result += class_entries
    result += valid_method_entry

    return result
