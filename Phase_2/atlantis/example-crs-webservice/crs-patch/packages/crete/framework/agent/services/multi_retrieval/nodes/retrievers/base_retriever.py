from abc import ABC, abstractmethod

from crete.framework.agent.services.multi_retrieval.nodes.base_node import BaseNode
from crete.framework.agent.services.multi_retrieval.states.retrieval_state import (
    RetrievalCategory,
    RetrievalQuery,
    RetrievalResult,
    RetrievalState,
)


class BaseRetriever(BaseNode, ABC):
    def __init__(
        self,
        query_category: RetrievalCategory,
        max_n_results_per_query: int = 8,
    ):
        super().__init__()
        self.query_category = query_category
        self.max_n_results_per_query = max_n_results_per_query

    def __call__(self, state: RetrievalState) -> dict[str, list[RetrievalResult]]:
        valid_queries: list[RetrievalQuery] = [
            q for q in state.queries if q.category == self.query_category
        ]

        results: list[RetrievalResult] = []
        for query in valid_queries:
            # Simple prioriry based sorting
            results.extend(
                sorted(self._retrieve(query), key=lambda x: x.priority, reverse=True)[
                    : self.max_n_results_per_query
                ]
            )

        return {"results": results}

    @abstractmethod
    def _retrieve(self, query: RetrievalQuery) -> list[RetrievalResult]:
        pass  # pragma: no cover
