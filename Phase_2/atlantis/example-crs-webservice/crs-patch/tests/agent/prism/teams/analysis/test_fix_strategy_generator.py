import os
import tempfile
from unittest.mock import Mock

import pytest
from crete.framework.agent.services.multi_retrieval.states.patch_state import (
    CodeSnippet,
)
from crete.framework.agent.services.prism.states.analysis_team_state import (
    AnalysisCell,
    AnalysisTeamState,
)
from crete.framework.agent.services.prism.teams.analysis.fix_strategy_generator import (
    FixStrategyGenerator,
)
from langchain_core.messages import AIMessage


@pytest.fixture
def fix_strategy_generator() -> FixStrategyGenerator:
    mock_fix_strategy_generator = FixStrategyGenerator(llm=Mock())
    mock_fix_strategy_generator.llm.invoke = Mock(
        return_value=AIMessage(content="test content")
    )
    return mock_fix_strategy_generator


@pytest.fixture
def state() -> AnalysisTeamState:
    return AnalysisTeamState()


def test_basic_call(
    fix_strategy_generator: FixStrategyGenerator, state: AnalysisTeamState
) -> None:
    state.evaluation_report = ""
    state.cells = [AnalysisCell()]
    with pytest.raises(ValueError):
        fix_strategy_generator(state)

    state.evaluation_report = "test evaluation report"
    state.n_fix_strategy_tries = 0
    state.cells = []
    result = fix_strategy_generator(state)
    assert result["analysis_report"] == ""
    assert result["relevant_code_snippets"] == ""
    assert result["n_fix_strategy_tries"] == 1

    state.cells = [
        AnalysisCell(
            code_snippets=[
                CodeSnippet(
                    file_path="test_file.py",
                    line_start=1,
                    line_end=2,
                )
            ],
            analysis="test analysis",
        )
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        full_file_path = os.path.join(temp_dir, "test_file.py")
        with open(full_file_path, "w") as f:
            f.write("def test_function():\n    pass\n")
        result = fix_strategy_generator(state)
        assert len(result["analysis_report"]) != 0


def test_format_cell_prompts(
    fix_strategy_generator: FixStrategyGenerator, state: AnalysisTeamState
) -> None:
    state.evaluation_report = "test evaluation report"
    state.cells = [
        AnalysisCell(
            code_snippets=[
                CodeSnippet(
                    file_path="test_file.py",
                    line_start=1,
                    line_end=2,
                    content="def test_function():\n    pass\n",
                )
            ],
            analysis="test analysis",
        )
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        full_file_path = os.path.join(temp_dir, "test_file.py")
        with open(full_file_path, "w") as f:
            f.write("def test_function():\n    pass\n")
        result = fix_strategy_generator._format_cell_prompts(  # type: ignore
            state.cells
        )
        assert "test_file.py:1-2" in result
        assert "def test_function():" in result
        assert "    pass" in result
        assert "test analysis" in result


def test_format_code_snippets(
    fix_strategy_generator: FixStrategyGenerator, state: AnalysisTeamState
) -> None:
    state.evaluation_report = "test evaluation report"
    state.cells = [
        AnalysisCell(
            code_snippets=[
                CodeSnippet(
                    file_path="test_file.py",
                    line_start=1,
                    line_end=2,
                    content="def test_function():\n    pass\n",
                )
            ],
            analysis="test analysis",
        )
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        state.repo_path = temp_dir
        full_file_path = os.path.join(temp_dir, "test_file.py")
        with open(full_file_path, "w") as f:
            f.write("def test_function():\n    pass\n")
        result = fix_strategy_generator._format_code_snippets(  # type: ignore
            state.cells
        )
        assert "test_file.py:1-2" in result
        assert "def test_function():" in result
        assert "    pass" in result
