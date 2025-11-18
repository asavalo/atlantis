import pytest
from crete.framework.agent.services.multi_retrieval.nodes.retrievers.base_retriever import (
    BaseRetriever,
)
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalQuery,
    RetrievalResult,
    RetrievalState,
)


@pytest.fixture
def base_retriever() -> BaseRetriever:
    class TestRetriever(BaseRetriever):
        def _retrieve(self, query: RetrievalQuery) -> list[RetrievalResult]:
            result = RetrievalResult()
            result.update_from_query(query)
            return [result]

    return TestRetriever(RetrievalCategory.CODE_SNIPPET)


@pytest.fixture
def state() -> RetrievalState:
    return RetrievalState()


def test_base_retriever_call(base_retriever: BaseRetriever, state: RetrievalState):
    base_retriever.query_category = RetrievalCategory.CODE_SNIPPET
    state.queries = [
        RetrievalQuery(
            query="test.py",
            category=RetrievalCategory.CODE_SNIPPET,
        ),
        RetrievalQuery(
            query="test.py",
            category=RetrievalCategory.FILE,
        ),
    ]
    results = base_retriever(state)
    assert len(results["results"]) == 1
    assert results["results"][0].query == "test.py"
    assert results["results"][0].category == RetrievalCategory.CODE_SNIPPET

    base_retriever.query_category = RetrievalCategory.FILE
    results = base_retriever(state)
    assert len(results["results"]) == 1
    assert results["results"][0].query == "test.py"
    assert results["results"][0].category == RetrievalCategory.FILE
