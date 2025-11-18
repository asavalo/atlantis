from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.iterating import IteratingAgent
from crete.framework.coder.services.aider import AiderCoder
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.fault_localizer.services.stacktrace import StacktraceFaultLocalizer
from python_llm.api.actors import LlmApiManager


@pytest.mark.skip(reason="This test is flaky and needs to be fixed.")
@pytest.mark.vcr()
def test_iterator(detection_c_itoa_cpv_1: tuple[Path, Path]):
    agent = IteratingAgent(
        fault_localizer=StacktraceFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
        coder_name=AiderCoder,
        count=3,
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_itoa_cpv_1,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actions = list(agent.act(context, detection=detection))

    assert len(actions) == 3
