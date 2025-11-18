import litellm
import pytest
from crete.framework.agent.services.swe import SweAgent
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.services.default import DefaultFaultLocalizer
from crete.framework.scheduler.tracker.llm_cost import LlmCostTracker
from python_llm.api.actors import LlmApiManager

from tests.agent.test_aider_agent import AiderAgent, HeadAction
from tests.conftest import Path


def test_litellm_tracker():
    tracker = LlmCostTracker(max_cost=1)
    with tracker.tracking():
        litellm.completion(  # pyright: ignore[reportUnknownMemberType]
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello, world!"}],
            mock_response="It's simple to use and easy to get started",
        )

    assert tracker._total_cost > 0  # pyright: ignore[reportPrivateUsage]
    assert not tracker.is_exhausted()


def test_llm_tracker_cost_exceeded():
    tracker = LlmCostTracker(max_cost=0.0001)
    with tracker.tracking():
        litellm.completion(  # pyright: ignore[reportUnknownMemberType]
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello, world!"}],
            mock_response="It's simple to use and easy to get started",
        )

    assert tracker.is_exhausted()


@pytest.mark.vcr()
def test_aider_cost_exceeded(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    tracker = LlmCostTracker(max_cost=0.0001)
    with tracker.tracking():
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

        next(agent.act(context, detection=detection))

    assert tracker.is_exhausted()


@pytest.mark.slow
@pytest.mark.vcr()
def test_swe_cost_exceeded(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    tracker = LlmCostTracker(max_cost=0.0001)
    with tracker.tracking():
        agent = SweAgent(
            fault_localizer=DefaultFaultLocalizer(),
            llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
        )

        context, detection = AIxCCContextBuilder(
            *detection_c_mock_cp_cpv_1,
            evaluator=DummyEvaluator(),
        ).build(
            previous_action=HeadAction(),
        )

        next(agent.act(context, detection=detection))

    assert tracker.is_exhausted()


def test_litellm_multiple_trackers():
    tracker1 = LlmCostTracker(max_cost=1)
    tracker2 = LlmCostTracker(max_cost=1)
    with tracker1.tracking():
        litellm.completion(  # pyright: ignore[reportUnknownMemberType]
            model="gpt-4o",
            messages=[{"role": "user", "content": "Hello, world!"}],
            mock_response="It's simple to use and easy to get started",
        )

        with tracker2.tracking():
            litellm.completion(  # pyright: ignore[reportUnknownMemberType]
                model="gpt-4o",
                messages=[{"role": "user", "content": "Hello, world!"}],
                mock_response="It's simple to use and easy to get started",
            )

    assert tracker1._total_cost > 0  # pyright: ignore[reportPrivateUsage]
    assert tracker2._total_cost > 0  # pyright: ignore[reportPrivateUsage]
    assert (
        tracker1._total_cost  # pyright: ignore[reportPrivateUsage]
        > tracker2._total_cost  # pyright: ignore[reportPrivateUsage]
    )
