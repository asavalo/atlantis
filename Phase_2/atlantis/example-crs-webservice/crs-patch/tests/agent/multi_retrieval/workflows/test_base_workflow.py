from typing import Any, Dict

import pytest
from crete.framework.agent.services.multi_retrieval.workflows.base_workflow import (
    BaseWorkflow,
)
from langchain_core.runnables.config import RunnableConfig


class MockWorkflow(BaseWorkflow):
    def compile(self, *args, **kwargs) -> Any:  # type: ignore
        return "compiled"

    def invoke(self, state: Any, config: RunnableConfig) -> Dict[str, Any]:
        return {"result": "invoked"}


@pytest.fixture
def mock_workflow() -> MockWorkflow:
    return MockWorkflow()


def test_compile(mock_workflow: MockWorkflow) -> None:
    assert mock_workflow.compile() == "compiled"  # type: ignore


def test_invoke(mock_workflow: MockWorkflow) -> None:
    config = RunnableConfig()
    result = mock_workflow.invoke(state={}, config=config)
    assert result == {"result": "invoked"}
