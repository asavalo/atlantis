import inspect
from unittest.mock import Mock

import pytest
from crete.framework.agent.services.prism.states.analysis_team_state import (
    AnalysisTeamState,
)
from crete.framework.agent.services.prism.teams.analysis.code_context_provider import (
    CodeContextProvider,
)
from langchain_core.messages import AIMessage


@pytest.fixture
def code_context_provider() -> CodeContextProvider:
    code_context_provider = CodeContextProvider(llm=Mock())
    code_context_provider.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    return code_context_provider


@pytest.fixture
def state() -> AnalysisTeamState:
    return AnalysisTeamState()


def test_basic_call(
    code_context_provider: CodeContextProvider, state: AnalysisTeamState
) -> None:
    state.evaluation_report = ""
    with pytest.raises(ValueError):
        code_context_provider(state)

    code_context_provider.max_n_interactions = 0
    with pytest.raises(ValueError):
        code_context_provider(state)

    code_context_provider.max_n_interactions = 1
    state.evaluation_report = "test evaluation report"
    code_context_provider.llm.invoke = Mock(
        return_value=AIMessage(
            content=inspect.cleandoc(
                """\
                <exploration_plan>
                ...
                </exploration_plan>
                <retrieve>
                <grep>example.using.fully.qualified.ClassName</grep>
                <grep>function_name</grep>
                <grep>variable_type_name</grep>
                </retrieve>
                <cells>
                <cell>
                <code_range>path/to/file_name.py:5-5</code_range>
                <analysis>
                ...
                </analysis>
                </cell>
                <cell>
                <code_range>path/to/file_name.py:10-20</code_range>
                <analysis>
                ...
                </analysis>
                </cell>
                </cells>
                """
            )
        )
    )
    code_context_provider.code_retriever_subgraph.retrieve_from_content = Mock(
        return_value="test retrieval"
    )
    result = code_context_provider(state)
    assert result["cells"][0].code_snippets[0].file_path == "path/to/file_name.py"
    assert result["cells"][0].code_snippets[0].line_start == 5
    assert result["cells"][0].code_snippets[0].line_end == 5
    assert result["cells"][0].analysis == "..."
    assert result["cells"][1].code_snippets[0].file_path == "path/to/file_name.py"
    assert result["cells"][1].code_snippets[0].line_start == 10
    assert result["cells"][1].code_snippets[0].line_end == 20
    assert result["cells"][1].analysis == "..."


def test_cells_from_message_content(code_context_provider: CodeContextProvider) -> None:
    content = inspect.cleandoc(
        """\
        <cells>
        <cell>
        <code_range>path/to/file_name1.py:10-20</code_range>
        <analysis>
        ...
        </analysis>
        </cell>
        <cell>
        <code_range>path/to/file_name2.py:30-40</code_range>
        <analysis>
        ...
        </analysis>
        </cell>
        </cells>
        """
    )
    cells = code_context_provider._cells_from_message_content(content)  # type: ignore
    assert len(cells) == 2
    assert len(cells[0].code_snippets) == 1
    assert cells[0].code_snippets[0].file_path == "path/to/file_name1.py"
    assert cells[0].code_snippets[0].line_start == 10
    assert cells[0].code_snippets[0].line_end == 20
    assert cells[0].analysis == "..."
    assert len(cells[1].code_snippets) == 1
    assert cells[1].code_snippets[0].file_path == "path/to/file_name2.py"
    assert cells[1].code_snippets[0].line_start == 30
    assert cells[1].code_snippets[0].line_end == 40
    assert cells[1].analysis == "..."
