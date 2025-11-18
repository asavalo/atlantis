import tempfile
from unittest.mock import Mock, patch

import pytest
from ast_grep_py import SgNode, SgRoot
from crete.framework.agent.services.multi_retrieval.nodes.retrievers.ast_grep_retriever import (
    ASTGrepRetriever,
)
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalQuery,
    RetrievalResult,
)


@pytest.fixture
def ast_grep_retriever() -> ASTGrepRetriever:
    return ASTGrepRetriever()


@pytest.fixture
def retrieval_query() -> RetrievalQuery:
    return RetrievalQuery(
        query="test_code",
        category=RetrievalCategory.CODE_SNIPPET,
        repo_path="/path/to/repo",
    )


def test_retrieve(
    ast_grep_retriever: ASTGrepRetriever, retrieval_query: RetrievalQuery
):
    ripgrep_result = RetrievalResult(
        file_path="test.txt",
        content="test_text",
        line_start=1,
        line_end=1,
    )
    with patch(
        "crete.framework.agent.services.multi_retrieval.nodes.retrievers.ripgrep_retriever.RipgrepRetriever._retrieve"
    ) as mock_retrieve:
        mock_retrieve.return_value = []
        retrieved = ast_grep_retriever._retrieve(retrieval_query)  # type: ignore
        assert retrieved == []

        with patch("os.path.exists", return_value=True):
            mock_retrieve.return_value = [ripgrep_result]
            retrieved = ast_grep_retriever._retrieve(retrieval_query)  # type: ignore
            assert len(retrieved) == 1
            assert retrieved[0].file_path == "test.txt"
            assert retrieved[0].file_lang == ""
            assert retrieved[0].content == "test_text"
            assert retrieved[0].line_start == 1
            assert retrieved[0].line_end == 1

            ripgrep_result.file_path = "test.c"
            file_src = """\
int add(int a, int b) {
    return a + b;
}
"""
            root_node = SgRoot(file_src, "c").root()
            ast_grep_retriever._get_root_node = Mock(return_value=(root_node, file_src))  # type: ignore
            retrieval_query.query = "add"
            retrieved = ast_grep_retriever._retrieve(retrieval_query)  # type: ignore

            assert len(retrieved) == 1
            assert (
                retrieved[0].content == "int add(int a, int b) {\n    return a + b;\n}"
            )
            assert retrieved[0].line_start == 1
            assert retrieved[0].line_end == 3

            ripgrep_result.file_path = "test.java"
            file_src = """\
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
"""
            root_node = SgRoot(file_src, "java").root()
            ast_grep_retriever._get_root_node = Mock(return_value=(root_node, file_src))  # type: ignore
            retrieval_query.query = "main"
            retrieved = ast_grep_retriever._retrieve(retrieval_query)  # type: ignore

            assert len(retrieved) == 1
            assert (
                retrieved[0].content
                == """\
    public static void main(String[] args) {
        System.out.println(\"Hello, World!\");
    }"""
            )
            assert retrieved[0].line_start == 2
            assert retrieved[0].line_end == 4


def test_language_from_file_path(ast_grep_retriever: ASTGrepRetriever):
    file_path_to_language = {
        "test.py": "python",
        "test.java": "java",
        "test.c": "c",
        "test.h": "c",
        "test.cpp": "cpp",
        "test.hpp": "cpp",
        "test.cc": "cpp",
        "test.hh": "cpp",
    }
    for file_path, language in file_path_to_language.items():
        assert ast_grep_retriever._language_from_file_path(file_path) == language  # type: ignore


def test_tag_languages(
    ast_grep_retriever: ASTGrepRetriever, retrieval_query: RetrievalQuery
):
    results = [
        RetrievalResult(
            file_path="test.py",
            content="test_code",
            line_start=1,
            line_end=1,
        ),
        RetrievalResult(
            file_path="test.java",
            content="test_code",
            line_start=1,
            line_end=1,
        ),
        RetrievalResult(
            file_path="test.c",
            content="test_code",
            line_start=1,
            line_end=1,
        ),
    ]
    langs = ["python", "java", "c"]
    ast_grep_retriever._tag_languages(results)  # type: ignore
    for i, result in enumerate(results):
        assert result.file_lang == langs[i]


def test_get_root_node(ast_grep_retriever: ASTGrepRetriever):
    code = "int add(int a, int b) {\n    return a + b;\n}"
    with tempfile.NamedTemporaryFile(suffix=".c") as temp_file:
        temp_file.write(code.encode("utf-8"))
        temp_file.flush()
        root_node, file_src = ast_grep_retriever._get_root_node(temp_file.name, "c")  # type: ignore
        assert isinstance(root_node, SgNode)
        assert file_src == code

    code_with_unicode_decode_error = (
        b"int add(int a, int b) {\n    // \x80\n    return a + b;\n}"
    )
    with tempfile.NamedTemporaryFile(suffix=".c") as temp_file:
        temp_file.write(code_with_unicode_decode_error)
        temp_file.flush()
        root_node, file_src = ast_grep_retriever._get_root_node(temp_file.name, "c")  # type: ignore
        assert isinstance(root_node, SgNode)
        assert file_src == code_with_unicode_decode_error.decode(
            "utf8", errors="replace"
        )


def test_retrieve_c_code(ast_grep_retriever: ASTGrepRetriever):
    file_src = """\
int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

struct Point {
    int x;
    int y;
};
"""
    root_node = SgRoot(file_src, "c").root()
    query = "add"

    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 1
    assert retrieved[0].content == "int add(int a, int b) {\n    return a + b;\n}"
    assert retrieved[0].line_start == 1
    assert retrieved[0].line_end == 3

    query = "sub"
    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 1
    assert retrieved[0].content == "int sub(int a, int b) {\n    return a - b;\n}"
    assert retrieved[0].line_start == 5
    assert retrieved[0].line_end == 7

    query = "dd"
    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 1
    assert retrieved[0].content == "int add(int a, int b) {\n    return a + b;\n}"
    assert retrieved[0].line_start == 1
    assert retrieved[0].line_end == 3

    query = "Point"
    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 1
    assert retrieved[0].content == "struct Point {\n    int x;\n    int y;\n};"
    assert retrieved[0].line_start == 9
    assert retrieved[0].line_end == 12

    # Error case that does not comform regex
    query = "add("
    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 0


def test_retrieve_errorneous_c_code(ast_grep_retriever: ASTGrepRetriever):
    file_src = """\
#define test_define

u_char * test_define
test_function1(u_char *a, ...)
{
    // Variadic function is not parsed in tree-sitter
    // but exists in some cases.
    // This is a test case for such a scenario.
    return a;
}

u_char *
test_function2(u_char *a)
{
    // Mismatching braces in the function is not parsed in tree-sitter
    // but exists in some cases.
    // This is a test case for such a scenario.
#if (test_define)
    if (a[0] == 't1') {
#else
    if (a[0] != 't2') {
#endif
        return a;
    }
    return a;
}

u_char *
test_function3(u_char *a)
{
    return a;
}
"""
    # This is a c code but parsed as cpp code since this handles the error cases.
    root_node = SgRoot(file_src, "cpp").root()
    query = "test_function1"
    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 1
    assert (
        retrieved[0].content
        == """\
u_char * test_define
test_function1(u_char *a, ...)
{
    // Variadic function is not parsed in tree-sitter
    // but exists in some cases.
    // This is a test case for such a scenario.
    return a;
}"""
    )
    assert retrieved[0].line_start == 3
    assert retrieved[0].line_end == 10

    query = "test_function2"
    retrieved = ast_grep_retriever._retrieve_c_code(query, root_node, file_src)  # type: ignore
    assert len(retrieved) == 1
    assert (
        retrieved[0].content
        == """\
u_char *
test_function2(u_char *a)
{
    // Mismatching braces in the function is not parsed in tree-sitter
    // but exists in some cases.
    // This is a test case for such a scenario.
#if (test_define)
    if (a[0] == 't1') {
#else
    if (a[0] != 't2') {
#endif
        return a;
    }
    return a;
}"""
    )
    assert retrieved[0].line_start == 12
    assert retrieved[0].line_end == 26


def test_retrieve_java_code(ast_grep_retriever: ASTGrepRetriever):
    test_file_path = "Test.java"
    file_src = """\
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
"""
    root_node = SgRoot(file_src, "java").root()
    query = "main"

    retrieved = ast_grep_retriever._retrieve_java_code(  # type: ignore
        query, root_node, file_src, test_file_path
    )
    assert len(retrieved) == 1
    assert (
        retrieved[0].content
        == """\
    public static void main(String[] args) {
        System.out.println(\"Hello, World!\");
    }"""
    )
    assert retrieved[0].line_start == 2
    assert retrieved[0].line_end == 4

    query = "Test"
    retrieved = ast_grep_retriever._retrieve_java_code(  # type: ignore
        query, root_node, file_src, test_file_path
    )
    assert len(retrieved) == 1
    assert (
        retrieved[0].content
        == """\
public class Test {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}"""
    )
    assert retrieved[0].line_start == 1
    assert retrieved[0].line_end == 5

    file_src = """\
package test;
import java.util.List;

public class Test {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}
"""
    root_node = SgRoot(file_src, "java").root()
    query = "main"

    retrieved = ast_grep_retriever._retrieve_java_code(  # type: ignore
        query, root_node, file_src, test_file_path
    )
    assert len(retrieved) == 2
    assert retrieved[0].content == "import java.util.List;"
    assert retrieved[0].line_start == 2
    assert retrieved[0].line_end == 2
    assert (
        retrieved[1].content
        == """\
    public static void main(String[] args) {
        System.out.println(\"Hello, World!\");
    }"""
    )
    assert retrieved[1].line_start == 5
    assert retrieved[1].line_end == 7

    # Error case that does not comform regex
    query = "Test("
    retrieved = ast_grep_retriever._retrieve_java_code(  # type: ignore
        query, root_node, file_src, test_file_path
    )
    assert len(retrieved) == 0


def test_split_java_query(ast_grep_retriever: ASTGrepRetriever):
    assert ast_grep_retriever._split_java_query("com.example.package.ClassName") == (  # type: ignore
        "ClassName",
        "com.example.package",
    )
    assert ast_grep_retriever._split_java_query(  # type: ignore
        "com.example.package.ClassName.method"
    ) == ("method", "com.example.package.ClassName")
    assert ast_grep_retriever._split_java_query(  # type: ignore
        "com.example.package.ClassName$InnerClass"
    ) == ("InnerClass", "com.example.package.ClassName")
    assert ast_grep_retriever._split_java_query(  # type: ignore
        "com.example.package.ClassName$InnerClass.method"
    ) == ("method", "com.example.package.ClassName$InnerClass")

    assert ast_grep_retriever._split_java_query("ClassName.method") == (  # type: ignore
        "method",
        "ClassName",
    )
    assert ast_grep_retriever._split_java_query("ClassName.method.") == (  # type: ignore
        "ClassName.method.",
        "",
    )
