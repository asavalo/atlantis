import inspect
from unittest.mock import Mock, patch

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.retrievers.ripgrep_retriever import (
    RipgrepRetriever,
)
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalQuery,
)


@pytest.fixture
def ripgrep_retriever() -> RipgrepRetriever:
    return RipgrepRetriever()


def test_run_ripgrep(ripgrep_retriever: RipgrepRetriever):
    query = "test_query"
    repo_path = "path/to/repo"

    subprocess_text_return = Mock()
    subprocess_text_return.stdout = bytes("test_output", "utf-8")
    with patch("subprocess.run", return_value=subprocess_text_return):
        log = ripgrep_retriever._run_ripgrep(query, repo_path)  # type: ignore
        assert log == "test_output"

    subprocess_text_return.stdout = bytes("", "utf-8")
    with patch("subprocess.run", return_value=subprocess_text_return):
        log = ripgrep_retriever._run_ripgrep(query, repo_path)  # type: ignore
        assert log == ""

    # Test non decodable output
    subprocess_text_return.stdout = b"\x80abc"
    with patch("subprocess.run", return_value=subprocess_text_return):
        log = ripgrep_retriever._run_ripgrep(query, repo_path)  # type: ignore
        assert log == "\ufffdabc"


def test_retrieve(ripgrep_retriever: RipgrepRetriever):
    query = RetrievalQuery(
        query="test_code",
        category=RetrievalCategory.CODE_SNIPPET,
        repo_path="/path/to/repo",
    )

    test_grep_log = inspect.cleandoc(
        """\
        /path/to/repo/test.py
        1: test 1
        2: test_code
        3: test 3
        """
    )

    ripgrep_retriever._run_ripgrep = Mock(  # type: ignore
        return_value=test_grep_log
    )
    retrieved = ripgrep_retriever._retrieve(query)  # type: ignore
    assert len(retrieved) == 1
    assert retrieved[0].content == inspect.cleandoc(
        """\
        1: test 1
        2: test_code
        3: test 3
        """
    )
    assert retrieved[0].file_path == "test.py"
    assert retrieved[0].line_start == 1
    assert retrieved[0].line_end == 3

    test_grep_log_multi = inspect.cleandoc(
        """\
        /path/to/repo/test.py
        1: test 1-1
        2: test_code
        3: test 1-3

        /path/to/repo/subdir/test2.py
        1: test 2-1
        2: test_code
        3: test 2-3
        """
    )
    ripgrep_retriever._run_ripgrep = Mock(  # type: ignore
        return_value=test_grep_log_multi
    )
    retrieved = ripgrep_retriever._retrieve(query)  # type: ignore
    assert len(retrieved) == 2
    assert retrieved[0].content == inspect.cleandoc(
        """\
        1: test 1-1
        2: test_code
        3: test 1-3
        """
    )
    assert retrieved[0].file_path == "test.py"
    assert retrieved[0].line_start == 1
    assert retrieved[0].line_end == 3
    assert retrieved[1].content == inspect.cleandoc(
        """\
        1: test 2-1
        2: test_code
        3: test 2-3
        """
    )
    assert retrieved[1].file_path == "subdir/test2.py"
    assert retrieved[1].line_start == 1
    assert retrieved[1].line_end == 3
    assert retrieved[1].content == inspect.cleandoc(
        """\
        1: test 2-1
        2: test_code
        3: test 2-3
        """
    )
