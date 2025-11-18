from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.coder.services.minimal import MinimalCoder
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.models import FaultLocation
from python_llm.api.actors import LlmApiManager


@pytest.mark.skip(reason="Skipping test .cache dir is changed")
def test_multiple_runs(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    environment = context["pool"].use(context, "CLEAN")
    assert environment is not None

    coder = MinimalCoder(
        agent_context=context,
        detection=detection,
        environment=environment,
        llm_api_manager=LlmApiManager.from_environment(
            model="claude-3-5-sonnet-20241022", custom_llm_provider="anthropic"
        ),
        fault_location=FaultLocation(
            file=context["pool"].source_directory / "mock_vp.c",
            function_name="func_a",
            line_range=None,
        ),
    )

    first_diff = coder.run(
        context, "Add a comment '// 0xdeadbeef' to the function func_a"
    )
    assert first_diff is not None
    assert "0xdeadbeef" in first_diff.decode()

    second_diff = coder.run(
        context, "Add a new comment '// 0xbadc0de' to the function func_a"
    )
    assert second_diff is not None
    assert "0xdeadbeef" in second_diff.decode()
    assert "0xbadc0de" in second_diff.decode()
