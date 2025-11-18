import os
import tempfile
from unittest.mock import Mock, patch

import pytest
from crete.framework.agent.services.multi_retrieval.nodes.retrievers.file_retriever import (
    FileRetriever,
)
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalQuery,
)


@pytest.fixture
def file_retriever() -> FileRetriever:
    return FileRetriever()


def test_retieve(file_retriever: FileRetriever):
    query = RetrievalQuery(
        query="test.py",
        repo_path="/path/to/repo",
        category=RetrievalCategory.CODE_SNIPPET,
    )
    retrieved = file_retriever._retrieve(query)  # type: ignore
    assert retrieved == []

    query.category = RetrievalCategory.FILE
    file_retriever._get_file_content = Mock(return_value=("file content", 1, 1))  # type: ignore
    file_retriever._rebase_file_path = Mock(return_value="path/to/test.py")  # type: ignore

    with patch("os.path.exists", return_value=False):
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert retrieved == []

    with patch("os.path.isfile", return_value=False):
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert retrieved == []

    with (
        patch("os.path.exists", return_value=True),
        patch("os.path.isfile", return_value=True),
    ):
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert len(retrieved) == 1
        assert retrieved[0].content == "file content"
        assert retrieved[0].file_path == "path/to/test.py"
        assert retrieved[0].line_start == 1
        assert retrieved[0].line_end == 1

        file_retriever._rebase_file_path = Mock(return_value=None)  # type: ignore
        query.query = "test.py"

        file_retriever._search_file_path_with_name = Mock(return_value=[])  # type: ignore
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert retrieved == []

        file_retriever._search_file_path_with_name = Mock(  # type: ignore
            return_value=["path/to/test.py"]
        )
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert len(retrieved) == 1
        assert retrieved[0].content == "file content"
        assert retrieved[0].file_path == "path/to/test.py"
        assert retrieved[0].line_start == 1
        assert retrieved[0].line_end == 1


def test_retrieve_temp_file(file_retriever: FileRetriever):
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file = os.path.join(temp_dir, "temp.txt")
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("Hello\nworld\n")

        query = RetrievalQuery(
            query="temp.txt",
            repo_path=temp_dir,
            category=RetrievalCategory.FILE,
        )
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert len(retrieved) == 1
        assert retrieved[0].content == "Hello\nworld\n"
        assert retrieved[0].file_path == "temp.txt"
        assert retrieved[0].line_start == 1
        assert retrieved[0].line_end == 2

        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("Hello\nworld")
        retrieved = file_retriever._retrieve(query)  # type: ignore
        assert len(retrieved) == 1
        assert retrieved[0].content == "Hello\nworld"
        assert retrieved[0].file_path == "temp.txt"
        assert retrieved[0].line_start == 1
        assert retrieved[0].line_end == 2


def test_rebase_file_path(file_retriever: FileRetriever):
    repo_path = "/path/to/repo"
    relative_file_path = "valid/path/to/subdir/test.py"
    absolute_file_path = "/path/to/repo/valid/path/to/subdir/test.py"

    def exists(path: str) -> bool:
        return path == absolute_file_path

    with (
        patch("os.path.exists", exists),
        patch("os.path.isfile", exists),
    ):
        query = "valid/path/to/subdir/test.py"
        result = file_retriever._rebase_file_path(query, repo_path)  # type: ignore
        assert result == relative_file_path

        query = "invalid/path/to/subdir/test.py"
        result = file_retriever._rebase_file_path(query, repo_path)  # type: ignore
        assert result is None

        query = "rebaseable/valid/path/to/subdir/test.py"
        result = file_retriever._rebase_file_path(query, repo_path)  # type: ignore
        assert result == relative_file_path

        query = "another/rebaseable/valid/path/to/subdir/test.py"
        result = file_retriever._rebase_file_path(query, repo_path)  # type: ignore
        assert result == relative_file_path


def test_get_file_content(file_retriever: FileRetriever):
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_path = os.path.join(temp_dir, "temp.py")
        with open(temp_file_path, "w", encoding="utf-8") as f:
            f.write("Hello\nworld\ntest\n")

        line_start = None
        line_end = None
        result = file_retriever._get_file_content(temp_file_path, line_start, line_end)  # type: ignore
        assert result == ("Hello\nworld\ntest\n", 1, 3)

        line_start = 2
        line_end = 3
        result = file_retriever._get_file_content(temp_file_path, line_start, line_end)  # type: ignore
        assert result == ("world\ntest\n", 2, 3)

        line_start = 1
        line_end = 1
        result = file_retriever._get_file_content(temp_file_path, line_start, line_end)  # type: ignore
        assert result == ("Hello\n", 1, 1)
