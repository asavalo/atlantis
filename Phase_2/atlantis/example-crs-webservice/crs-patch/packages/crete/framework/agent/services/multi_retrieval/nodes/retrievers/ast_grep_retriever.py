import os
from pathlib import Path
from typing import Any

from ast_grep_py import SgNode, SgRoot

from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalPriority,
    RetrievalQuery,
    RetrievalResult,
)

from .ripgrep_retriever import RipgrepRetriever

# TODO: Add other language supports
ASTGREP_RETREIVER_SUPPORTED_LANGUAGES = ("c", "java")


class ASTGrepRetriever(RipgrepRetriever):
    # TODO: Handle code retrieval for other languages (Python)
    def __init__(
        self,
        add_line_numbers: bool = False,
        consecutive_import_line_threshold: int = 5,
        n_context_lines: int = 5,
        max_n_results_per_query: int = 8,
        encoding: str = "utf-8",
        whold_word_retrieval_priority: RetrievalPriority = RetrievalPriority.MEDIUM,
        partial_word_retrieval_priority: RetrievalPriority = RetrievalPriority.LOW,
    ):
        super().__init__(
            n_context_lines=n_context_lines,
            max_n_results_per_query=max_n_results_per_query,
        )
        self.add_line_numbers = add_line_numbers
        self.whold_word_retrieval_priority = whold_word_retrieval_priority
        self.partial_word_retrieval_priority = partial_word_retrieval_priority
        self.consecutive_import_line_threshold = consecutive_import_line_threshold
        self.encoding = encoding

    def _retrieve(self, query: RetrievalQuery) -> list[RetrievalResult]:
        if query.query is None or query.query == "":
            return []
        if query.repo_path is None or query.repo_path == "":
            return []
        ripgrep_results = super()._retrieve(query)
        if len(ripgrep_results) == 0:
            return []

        # Tag languages
        self._tag_languages(ripgrep_results)

        # Retrieve
        ast_retrieved_files: set[str] = set()
        results: list[RetrievalResult] = []
        for result in ripgrep_results:
            if result.file_path is None:
                continue
            full_file_path = os.path.join(query.repo_path, result.file_path)
            if not os.path.exists(full_file_path):
                continue

            if result.file_lang not in ASTGREP_RETREIVER_SUPPORTED_LANGUAGES:
                # Fallback to ripgrep retrieval
                results.append(result)
                continue

            if full_file_path in ast_retrieved_files:
                continue

            ast_results: list[RetrievalResult] = []
            root_node, file_src = self._get_root_node(full_file_path, result.file_lang)
            if result.file_lang == "c":
                ast_results = self._retrieve_c_code(
                    query.query,
                    root_node,
                    file_src,
                )
                # Fallback to cpp parsed retrieval
                if len(ast_results) == 0:
                    root_node, file_src = self._get_root_node(full_file_path, "cpp")
                    ast_results = self._retrieve_c_code(
                        query.query,
                        root_node,
                        file_src,
                    )
            elif result.file_lang == "java":
                ast_results = self._retrieve_java_code(
                    query.query,
                    root_node,
                    file_src,
                    full_file_path,
                )

            if len(ast_results) == 0:
                # Fallback to ripgrep retrieval
                results.append(result)
                continue

            for ast_result in ast_results:
                ast_result.file_lang = result.file_lang
                ast_result.file_path = result.file_path

                # Note: We add line numbers here since ripgrep has line numbers by default
                if self.add_line_numbers:
                    ast_result.add_line_numbers()

            ast_retrieved_files.add(full_file_path)
            results.extend(ast_results)

        for result in results:
            result.update_from_query(query)
        return results

    def _language_from_file_path(self, file_path: str) -> str:
        file_extention = Path(file_path).suffix.lower()
        lang = ""
        if file_extention in (".c", ".h"):
            lang = "c"
        elif file_extention in (".cpp", ".hpp", ".cc", ".hh"):
            lang = "cpp"
        elif file_extention == ".java":
            lang = "java"
        elif file_extention == ".py":
            lang = "python"
        return lang

    def _tag_languages(self, results: list[RetrievalResult]) -> None:
        for result in results:
            if result.file_path is None:
                continue
            result.file_lang = self._language_from_file_path(result.file_path)

    def _get_root_node(self, file_path: str, lang: str) -> tuple[SgNode, str]:
        with open(file_path, "r", encoding=self.encoding, errors="replace") as f:
            file_src = f.read()
        return SgRoot(file_src, lang).root(), file_src

    def _retrieve_c_code(
        self,
        query: str,
        root_node: SgNode,
        file_src: str,
    ) -> list[RetrievalResult]:
        ast_retrievals: list[RetrievalResult] = []

        whole_word_regex = rf"\b{query}\b"
        partial_regex = query
        for regex in (whole_word_regex, partial_regex):
            try:
                ast_retrievals.extend(
                    self._retrieve_function_definition(regex, root_node, file_src)
                    + self._retrieve_type_definition(regex, root_node, file_src)
                )
                if len(ast_retrievals) == 0:
                    ast_retrievals.extend(
                        self._retrieve_function_definition(
                            regex, root_node, file_src, strict=False
                        )
                    )
            except RuntimeError:
                continue
            if regex == whole_word_regex:
                for retrieval in ast_retrievals:
                    retrieval.priority = self.whold_word_retrieval_priority
            else:
                for retrieval in ast_retrievals:
                    retrieval.priority = self.partial_word_retrieval_priority
            if len(ast_retrievals) > 0:
                break
        return ast_retrievals

    def _parse_java_aux_query(
        self, aux_query: str, full_file_path: str
    ) -> tuple[str, bool]:
        parent_query = ""
        is_queried_file_path = False
        if aux_query != "":
            aux_query_splits = aux_query.split(".")
            file_path_check_splits: list[str] = []
            for split in aux_query_splits:
                if "$" not in split:
                    file_path_check_splits.append(split)
                else:
                    break
            if "$" in aux_query_splits[-1]:
                parent_query = aux_query_splits[-1].rsplit("$", 1)[1]
            else:
                parent_query = aux_query_splits[-1]

            # NOTE: This can have false positives
            check_file_path = os.path.join(*file_path_check_splits)
            if check_file_path + "." in full_file_path:
                # full_file_path ends with the check_file_path (without extension)
                is_queried_file_path = True
            elif os.path.join(check_file_path, "") in full_file_path:
                # full_file_path contains the check_file_path in the middle
                is_queried_file_path = True
        return parent_query, is_queried_file_path

    def _split_java_query(self, query: str) -> tuple[str, str]:
        aux_query = ""
        if "." in query and not query.endswith("."):
            aux_query, query = query.rsplit(".", maxsplit=1)
        if "$" in query:
            aux_query_to_add, query = query.rsplit("$", maxsplit=1)
            aux_query = f"{aux_query}.{aux_query_to_add}"
        return query, aux_query

    def _retrieve_java_code(
        self,
        query: str,
        root_node: SgNode,
        file_src: str,
        full_file_path: str,
        retrieve_imports: bool = True,
    ) -> list[RetrievalResult]:
        ast_retrievals: list[RetrievalResult] = []
        query, aux_query = self._split_java_query(query)

        parent_query = ""
        is_queried_file_path = False
        if aux_query != "":
            parent_query, is_queried_file_path = self._parse_java_aux_query(
                aux_query, full_file_path
            )

        regex_to_retrieve: list[tuple[str, str]] = []
        whole_word_full_regex = rf"\b{aux_query}.{query}\b"
        if aux_query != "":
            regex_to_retrieve.append((whole_word_full_regex, ""))

        whole_word_regex = rf"\b{query}\b"
        partial_regex = query
        if parent_query != "":
            regex_to_retrieve.append((whole_word_regex, parent_query))
        regex_to_retrieve.append((whole_word_regex, ""))
        if parent_query != "":
            regex_to_retrieve.append((partial_regex, parent_query))
        regex_to_retrieve.append((partial_regex, ""))

        for regex, parent_regex in regex_to_retrieve:
            try:
                ast_retrievals.extend(
                    self._retrieve_method_declaration(
                        regex, root_node, file_src, parent_regex=parent_regex
                    )
                    + self._retrieve_class_declaration(
                        regex, root_node, file_src, parent_regex=parent_regex
                    )
                    + self._retrieve_interface_declaration(
                        regex, root_node, file_src, parent_regex=parent_regex
                    )
                    + self._retrieve_annotation_type_declaration(
                        regex, root_node, file_src, parent_regex=parent_regex
                    )
                )
            except RuntimeError:
                continue
            if (
                regex in (whole_word_full_regex, whole_word_regex)
                and is_queried_file_path
            ):
                for retrieval in ast_retrievals:
                    retrieval.priority = self.whold_word_retrieval_priority
            else:
                for retrieval in ast_retrievals:
                    retrieval.priority = self.partial_word_retrieval_priority
            if len(ast_retrievals) > 0:
                break

        # For Java, import declarations are also important context
        if retrieve_imports and len(ast_retrievals) > 0:
            import_retrievals = self._retrieve_import_declarations(root_node, file_src)
            if len(import_retrievals) > 0:
                max_priority = max(retrieval.priority for retrieval in ast_retrievals)
                for retrieval in import_retrievals:
                    retrieval.priority = max_priority
            ast_retrievals = import_retrievals + ast_retrievals
        return ast_retrievals

    def _retrieve_code_from_node(self, node: SgNode, file_src: str) -> dict[str, Any]:
        # node.range() starts from 0, so we add 1 to get the line numbers
        line_start = node.range().start.line + 1
        line_end = node.range().end.line + 1

        # Instead of sg_node.text(), we extract the code using the line numbers.
        # This is due to string formatting issues in the text() method
        # which does not return the exact code in the source file.
        return self._retrieve_code_from_lines(line_start, line_end, file_src)

    def _retrieve_code_from_lines(
        self, line_start: int, line_end: int, file_src: str
    ) -> dict[str, Any]:
        code_lines = file_src.split("\n")[line_start - 1 : line_end]
        return {
            "content": "\n".join(code_lines),
            "line_start": line_start,
            "line_end": line_end,
        }

    def _find_fuction_definition_nodes(
        self, root_node: SgNode, regex: str, strict: bool = True
    ) -> list[SgNode]:
        if strict:
            function_definition_nodes = root_node.find_all(
                regex=regex,
                kind="function_definition",
                has={
                    "kind": "function_declarator",
                    "regex": regex,
                    "field": "declarator",
                    "stopBy": "end",
                    "has": {
                        "kind": "identifier",
                        "regex": regex,
                        "field": "declarator",
                        "stopBy": "neighbor",
                    },
                },
            )
        else:
            function_definition_nodes = root_node.find_all(
                regex=regex,
                kind="function_definition",
                has={
                    "kind": "function_declarator",
                    "regex": regex,
                    "field": "declarator",
                    "stopBy": "end",
                    "has": {
                        "kind": "identifier",
                        "regex": regex,
                        "stopBy": "end",
                    },
                },
            )
        return function_definition_nodes

    def _find_preproc_function_def_nodes(
        self, root_node: SgNode, regex: str
    ) -> list[SgNode]:
        return root_node.find_all(
            regex=regex,
            kind="preproc_function_def",
            has={"kind": "identifier", "regex": regex, "stopBy": "neighbor"},
        )

    def _retrieve_function_definition_from_error_node(
        self, error_node: SgNode, regex: str, file_src: str
    ) -> RetrievalResult | None:
        """Retrieve function definition from error node.

        This handles the case where tree-sitter failed to parse function definition.
        """
        if error_node.kind() != "ERROR":
            return None
        # NOTE: node.range() starts from 0.
        line_start = error_node.range().start.line + 1
        line_end = error_node.range().end.line + 1
        if line_end - line_start <= self.n_context_lines:
            # error_node + compound_statement is the function definition.
            next_node = error_node.next()
            if next_node is None or next_node.kind() != "compound_statement":
                return None
            line_end = next_node.range().end.line + 1
            if line_end - line_start > self.n_context_lines:
                return RetrievalResult(
                    **self._retrieve_code_from_lines(line_start, line_end, file_src),
                )
            # ripgrep retrieval is sufficient.
            return None

        # function_declarator exists but failed to found function_definition.
        function_declarator_node = error_node.find(
            kind="function_declarator",
            has={
                "kind": "identifier",
                "regex": regex,
                "field": "declarator",
                "stopBy": "end",
            },
        )
        if function_declarator_node is None:
            return None
        other_definition_nodes = error_node.find_all(kind="function_definition")
        if len(other_definition_nodes) == 0:
            return RetrievalResult(
                **self._retrieve_code_from_node(error_node, file_src),
            )

        # NOTE: other_definition_nodes are already sorted by line number without overlap.
        full_code_lines = file_src.split("\n")
        function_declarator_line_start = function_declarator_node.range().start.line + 1
        function_declarator_line_end = function_declarator_node.range().end.line + 1
        other_definition_nodes = error_node.find_all(kind="function_definition")
        for i, def_node in enumerate(other_definition_nodes):
            def_node_line_start = def_node.range().start.line + 1
            def_node_line_end = def_node.range().end.line + 1
            if def_node_line_end < function_declarator_line_start:
                line_start = def_node_line_end + 1
            elif def_node_line_start > function_declarator_line_end:
                line_end = def_node_line_start - 1
                break

        # Remove lines that are empty
        if (
            line_start >= len(full_code_lines)
            or line_end >= len(full_code_lines)
            or line_start < 1
            or line_end < 1
        ):
            return None
        for i in range(line_start - 1, line_end):
            if full_code_lines[i] != "":
                line_start = i + 1
                break
        for i in range(line_end - 1, line_start - 2, -1):
            if full_code_lines[i] != "":
                line_end = i + 1
                break
        if line_start >= line_end or line_end - line_start <= self.n_context_lines:
            return None
        return RetrievalResult(
            **self._retrieve_code_from_lines(line_start, line_end, file_src),
        )

    def _retrieve_function_definition(
        self, regex: str, root_node: SgNode, file_src: str, strict: bool = True
    ) -> list[RetrievalResult]:
        """Retrieve function definitions in the given file.

        Tested languages: c
        """
        retrieval_results: list[RetrievalResult] = []

        # Find function_definition nodes
        function_definition_nodes = self._find_fuction_definition_nodes(
            root_node, regex, strict=strict
        )
        for node in function_definition_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )

        # Fallback to preproc_function_def if function_definition not found
        if len(retrieval_results) > 0:
            return retrieval_results
        preproc_function_def_nodes = self._find_preproc_function_def_nodes(
            root_node, regex
        )
        for node in preproc_function_def_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )

        if len(retrieval_results) > 0 or strict:
            return retrieval_results

        # Handle error case where tree-sitter failed to parse function definition
        # Case 1: function_declarator exists but failed to found function_definition
        error_node = root_node.find(
            regex=regex,
            kind="ERROR",
            has={
                "kind": "function_declarator",
                "regex": regex,
                "stopBy": "end",
                "has": {
                    "kind": "identifier",
                    "regex": regex,
                    "field": "declarator",
                    "stopBy": "end",
                },
            },
        )
        if error_node is None:
            # Case 2: binary_expression exists instead of function_declarator
            # This is usually the case for variadics that is only parsed as cpp
            error_node = root_node.find(
                regex=regex,
                kind="ERROR",
                has={
                    "kind": "binary_expression",
                    "regex": regex,
                    "stopBy": "neighbor",
                    "has": {
                        "kind": "identifier",
                        "regex": regex,
                        "stopBy": "end",
                    },
                },
            )
        if error_node is None:
            return retrieval_results

        retrieval_result = self._retrieve_function_definition_from_error_node(
            error_node, regex, file_src
        )
        if retrieval_result is not None:
            retrieval_results.append(retrieval_result)
        return retrieval_results

    def _retrieve_type_definition(
        self, regex: str, root_node: SgNode, file_src: str
    ) -> list[RetrievalResult]:
        """Retrieve type definitions in the given file.

        Tested languages: c
        """
        retrieval_results: list[RetrievalResult] = []

        type_definition_nodes = root_node.find_all(
            regex=regex,
            kind="type_definition",
            has={
                "kind": "type_identifier",
                "regex": regex,
                "field": "declarator",
                "stopBy": "end",
            },
        )
        for node in type_definition_nodes:
            type_identifier_node = node.find(kind="type_identifier", regex=regex)
            if type_identifier_node is None:
                continue
            elif type_identifier_node.inside(kind="parameter_list"):
                continue
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )
            if node.has(kind="field_declaration_list"):
                continue

            # Provide additional struct for type_definition without field_declaration_list
            struct_specifier_node = node.find(kind="struct_specifier")
            if struct_specifier_node is not None:
                struct_name_node = struct_specifier_node.find(kind="type_identifier")
                if struct_name_node is not None:
                    struct_name_regex = rf"\b{struct_name_node.text()}\b"
                    struct_nodes = root_node.find_all(
                        regex=struct_name_regex,
                        kind="struct_specifier",
                        has={"kind": "field_declaration_list", "stopBy": "neighbor"},
                    )
                    for struct_node in struct_nodes:
                        retrieval_results.append(
                            RetrievalResult(
                                **self._retrieve_code_from_node(struct_node, file_src),
                            )
                        )

        # Fallback to struct_specifier if type_definition not found
        if len(retrieval_results) > 0:
            return retrieval_results
        struct_specifier_nodes = root_node.find_all(
            regex=regex,
            kind="struct_specifier",
            has={"kind": "type_identifier", "regex": regex, "stopBy": "neighbor"},
        )
        for node in struct_specifier_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )

        # Fallback to preproc_def
        if len(retrieval_results) > 0:
            return retrieval_results
        preproc_def_nodes = root_node.find_all(
            regex=regex,
            kind="preproc_def",
            has={"kind": "identifier", "regex": regex, "stopBy": "neighbor"},
        )
        for node in preproc_def_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )

        return retrieval_results

    def _retrieve_method_declaration(
        self,
        regex: str,
        root_node: SgNode,
        file_src: str,
        parent_regex: str = "",
    ) -> list[RetrievalResult]:
        """Retrieve method declaration in the given file.

        Tested languages: java
        """
        retrieval_results: list[RetrievalResult] = []

        method_declaration_nodes = []
        if parent_regex != "":
            method_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="method_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
                inside={
                    "kind": "class_declaration",
                    "has": {
                        "kind": "identifier",
                        "regex": parent_regex,
                        "field": "name",
                    },
                    "stopBy": "end",
                },
            )
        else:
            method_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="method_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
            )

        for node in method_declaration_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )
        return retrieval_results

    def _retrieve_class_declaration(
        self,
        regex: str,
        root_node: SgNode,
        file_src: str,
        parent_regex: str = "",
    ) -> list[RetrievalResult]:
        """Retrieve class declaration in the given file.

        Tested languages: java
        """
        retrieval_results: list[RetrievalResult] = []

        class_declaration_nodes = []
        if parent_regex != "":
            class_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="class_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
                inside={
                    "kind": "class_declaration",
                    "has": {
                        "kind": "identifier",
                        "regex": parent_regex,
                        "field": "name",
                    },
                    "stopBy": "end",
                },
            )
        else:
            class_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="class_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
            )

        for node in class_declaration_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )
        return retrieval_results

    def _retrieve_interface_declaration(
        self,
        regex: str,
        root_node: SgNode,
        file_src: str,
        parent_regex: str = "",
    ) -> list[RetrievalResult]:
        """Retrieve interface declaration in the given file.

        Tested languages: java
        """
        retrieval_results: list[RetrievalResult] = []

        interface_declaration_nodes = []
        if parent_regex != "":
            interface_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="interface_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
                inside={
                    "kind": "class_declaration",
                    "has": {
                        "kind": "identifier",
                        "regex": parent_regex,
                        "field": "name",
                    },
                    "stopBy": "end",
                },
            )
        else:
            interface_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="interface_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
            )

        for node in interface_declaration_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )
        return retrieval_results

    def _retrieve_annotation_type_declaration(
        self,
        regex: str,
        root_node: SgNode,
        file_src: str,
        parent_regex: str = "",
    ) -> list[RetrievalResult]:
        """Retrieve interface declaration in the given file.

        Tested languages: java
        """
        retrieval_results: list[RetrievalResult] = []

        annotation_type_declaration_nodes = []
        if parent_regex != "":
            annotation_type_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="annotation_type_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
                inside={
                    "kind": "class_declaration",
                    "has": {
                        "kind": "identifier",
                        "regex": parent_regex,
                        "field": "name",
                    },
                    "stopBy": "end",
                },
            )
        else:
            annotation_type_declaration_nodes = root_node.find_all(
                regex=regex,
                kind="annotation_type_declaration",
                has={
                    "kind": "identifier",
                    "regex": regex,
                    "field": "name",
                    "stopBy": "neighbor",
                },
            )

        for node in annotation_type_declaration_nodes:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(node, file_src),
                )
            )
        return retrieval_results

    def _retrieve_import_declarations(
        self,
        root_node: SgNode,
        file_src: str,
    ) -> list[RetrievalResult]:
        """Retrieve import declarations in the given file.

        Tested languages: java
        """
        retrieval_results: list[RetrievalResult] = []

        import_declaration_nodes = root_node.find_all(kind="import_declaration")
        if len(import_declaration_nodes) == 0:
            return retrieval_results

        if len(import_declaration_nodes) == 1:
            retrieval_results.append(
                RetrievalResult(
                    **self._retrieve_code_from_node(
                        import_declaration_nodes[0], file_src
                    ),
                )
            )
        else:
            first_import_line_start = import_declaration_nodes[0].range().start.line + 1
            first_import_line_end = import_declaration_nodes[0].range().end.line + 1
            consecutive_import_lines = [
                [first_import_line_start, first_import_line_end]
            ]
            for node in import_declaration_nodes[1:]:
                line_start = node.range().start.line + 1
                line_end = node.range().end.line + 1
                if (
                    line_start
                    < consecutive_import_lines[-1][1]
                    + self.consecutive_import_line_threshold
                ):
                    consecutive_import_lines[-1][1] = line_end
                else:
                    consecutive_import_lines.append([line_start, line_end])

            for line_start, line_end in consecutive_import_lines:
                retrieval_results.append(
                    RetrievalResult(
                        content="\n".join(
                            file_src.split("\n")[line_start - 1 : line_end]
                        ),
                        line_start=line_start,
                        line_end=line_end,
                    )
                )
        return retrieval_results
