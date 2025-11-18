from pathlib import Path

import pytest
from crete.atoms.action import (
    CompilableDiffAction,
    HeadAction,
    NoPatchAction,
    SoundDiffAction,
    UnknownErrorAction,
    VulnerableDiffAction,
)
from crete.framework.agent.services.aider import AiderAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.fault_localizer.services.default import DefaultFaultLocalizer
from crete.framework.fault_localizer.services.sarif import SarifFaultLocalizer
from crete.framework.fault_localizer.services.stacktrace import StacktraceFaultLocalizer
from pytest_mock.plugin import MockerFixture
from python_llm.api.actors import LlmApiManager


@pytest.mark.integration
@pytest.mark.vcr()
def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    agent = AiderAgent(
        fault_localizer=StacktraceFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(agent.act(context, detection=detection))
    assert isinstance(action, SoundDiffAction)


@pytest.mark.integration
@pytest.mark.vcr()
def test_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    agent = AiderAgent(
        fault_localizer=StacktraceFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(agent.act(context, detection=detection))

    # Test that mock java creates a valid diff action
    # Note: Creating SoundDiffAction is very challenging in mock java
    assert isinstance(
        action, (SoundDiffAction, VulnerableDiffAction, CompilableDiffAction)
    )


@pytest.mark.integration
@pytest.mark.vcr()
def test_aider_sarif_report(detection_c_asc_nginx_cpv_1_sarif_only: tuple[Path, Path]):
    agent = AiderAgent(
        fault_localizer=SarifFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1_sarif_only,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(agent.act(context, detection=detection))

    assert not isinstance(action, (UnknownErrorAction, NoPatchAction)), (
        f"Unexpected action: {action}"
    )


@pytest.mark.vcr()
def test_unknown_error_on_aider(
    mocker: MockerFixture, detection_c_mock_cp_cpv_1: tuple[Path, Path]
):
    mocker.patch(
        "crete.framework.coder.services.aider.AiderCoder.run",
        return_value="",
    )

    agent = AiderAgent(
        fault_localizer=DefaultFaultLocalizer(),
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    action = next(agent.act(context, detection=detection))
    assert isinstance(action, NoPatchAction)
