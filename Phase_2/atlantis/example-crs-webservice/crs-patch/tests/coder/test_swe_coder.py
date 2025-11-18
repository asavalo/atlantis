from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.coder.services.swe import SweCoder
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from python_llm.api.actors import LlmApiManager


@pytest.mark.slow
@pytest.mark.vcr()
def test_multiple_runs(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    coder = SweCoder(
        agent_context=context,
        detection=detection,
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    first_diff = coder.run(
        context, "change the function name from 'func_a' to 'function_deadbeef'"
    )
    assert first_diff is not None, "First diff is None"
    assert "deadbeef" in first_diff.decode(), "First diff does not contain deadbeef"

    second_diff = coder.run(
        context, "change the function name from 'func_b' to 'function_badc0de'"
    )
    assert second_diff is not None, "Second diff is None"
    assert "deadbeef" in second_diff.decode(), "Second diff does not contain deadbeef"
    assert "badc0de" in second_diff.decode(), "Second diff does not contain badc0de"

    context["pool"].restore(context)
