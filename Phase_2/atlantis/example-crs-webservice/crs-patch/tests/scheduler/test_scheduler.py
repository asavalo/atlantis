import pytest
from crete.atoms.action import SoundDiffAction
from crete.framework.agent.protocols import AgentProtocol
from crete.framework.scheduler.contexts import SchedulingContext
from crete.framework.scheduler.services.round_robin import RoundRobinScheduler
from crete.framework.scheduler.tracker import DefaultTracker
from pytest_mock import MockerFixture


@pytest.fixture
def context() -> SchedulingContext:
    return {"llm_cost_limit": 10.0, "timeout": 100}


@pytest.fixture
def agents(mocker: MockerFixture) -> list[AgentProtocol]:
    return [mocker.Mock(spec=AgentProtocol) for _ in range(3)]


def test_schedule_single_round(context: SchedulingContext, agents: list[AgentProtocol]):
    # Setup
    scheduler = RoundRobinScheduler(early_exit=False, max_rounds=1)

    # Execute
    result = list(scheduler.schedule(context, agents))

    # Verify
    assert result == agents


def test_schedule_multiple_rounds(
    context: SchedulingContext, agents: list[AgentProtocol]
):
    # Setup
    scheduler = RoundRobinScheduler(early_exit=False, max_rounds=2)

    # Execute
    result = list(scheduler.schedule(context, agents))

    # Verify - should yield each agent twice (2 rounds)
    assert result == agents + agents


def test_feedback_and_early_exit(
    context: SchedulingContext,
    agents: list[AgentProtocol],
    mocker: MockerFixture,
):
    # Setup
    scheduler = RoundRobinScheduler(early_exit=True)
    sound_diff_action = mocker.Mock(spec=SoundDiffAction)

    # First run without any feedback (should return all agents)
    initial_result = list(scheduler.schedule(context, agents))
    assert initial_result == agents

    # Execute again - this should exit early
    scheduler.feedback(agents[0], sound_diff_action)
    early_exit_result = list(scheduler.schedule(context, agents))

    # Verify - should be empty due to early exit condition
    assert early_exit_result == []


def test_no_early_exit_when_disabled(
    context: SchedulingContext,
    agents: list[AgentProtocol],
    mocker: MockerFixture,
):
    # Setup (early_exit is False)
    scheduler = RoundRobinScheduler(early_exit=False)
    sound_diff_action = mocker.Mock(spec=SoundDiffAction)

    # Execute - this should NOT exit early since early_exit is False
    scheduler.feedback(agents[0], sound_diff_action)
    result = list(scheduler.schedule(context, agents))

    # Verify - should return all agents
    assert result == agents


def test_resource_exhaustion_exit(
    context: SchedulingContext,
    agents: list[AgentProtocol],
    mocker: MockerFixture,
):
    # Setup
    scheduler = RoundRobinScheduler(early_exit=False)

    # Create a mock tracker that reports as exhausted
    mock_tracker = mocker.Mock(spec=DefaultTracker)
    mock_tracker.tracking.return_value.__enter__ = mocker.Mock()
    mock_tracker.tracking.return_value.__exit__ = mocker.Mock()
    mock_tracker.is_exhausted.return_value = True

    # Patch the DefaultTracker to return our mock
    mocker.patch(
        "crete.framework.scheduler.services.round_robin.DefaultTracker",
        return_value=mock_tracker,
    )

    # Execute
    result = list(scheduler.schedule(context, agents))

    # Verify - should be empty due to resource exhaustion
    assert result == []
