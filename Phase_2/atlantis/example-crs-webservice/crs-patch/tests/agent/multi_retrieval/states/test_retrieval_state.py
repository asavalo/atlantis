from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalQuery,
    RetrievalResult,
)


def test_retrieval_result_update_from_query():
    result = RetrievalResult()
    query = RetrievalQuery(
        query="test_code",
        repo_path="/path/to/repo",
    )
    result.update_from_query(query)
    assert result.query == "test_code"
    assert result.repo_path == "/path/to/repo"


def test_add_line_numbers():
    test_content = "".join([f"line {i + 1}\n" for i in range(5)])
    result = RetrievalResult(
        content=test_content,
        line_start=1,
        line_end=5,
    )

    result.add_line_numbers()
    assert result.content == "".join([f"{i + 1}:line {i + 1}\n" for i in range(5)])

    result.content = test_content
    result.line_start = 6
    result.line_end = 10
    result.add_line_numbers()
    assert result.content == "".join([f"{i + 6}:line {i + 1}\n" for i in range(5)])

    result.content = test_content[:-1]
    result.line_start = 1
    result.line_end = 5
    result.add_line_numbers()
    assert result.content == "".join([f"{i + 1}:line {i + 1}\n" for i in range(5)])

    result.content = test_content
    result.line_start = 1
    result.line_end = 6
    result.add_line_numbers()
    assert (
        result.content
        == "".join([f"{i + 1}:line {i + 1}\n" for i in range(5)]) + "6:\n"
    )

    result.content = test_content + "\n"
    result.line_start = 1
    result.line_end = 6
    result.add_line_numbers()
    assert (
        result.content
        == "".join([f"{i + 1}:line {i + 1}\n" for i in range(5)]) + "6:\n"
    )
