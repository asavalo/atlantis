import pytest
from crs_patch.services.scheduler import RoundRobinScheduler


class MockRunner:
    def __init__(self, id: str):
        self.id = id

    def __str__(self):
        return self.id


class MockTask:
    def __init__(self, id: str):
        self.id = id

    def __str__(self):
        return self.id


@pytest.fixture
def scheduler():
    return RoundRobinScheduler[MockTask, MockRunner]()


def test_put_and_get_next_task(scheduler: RoundRobinScheduler[MockTask, MockRunner]):
    # Given
    task1 = MockTask("task1")
    task2 = MockTask("task2")
    runners1 = [MockRunner("runner1"), MockRunner("runner2")]
    runners2 = [MockRunner("runner3")]

    # When
    scheduler.put(task1, runners1)
    scheduler.put(task2, runners2)

    # Then
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task1"
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task2"
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task1"  # Round robin should cycle back


def test_get_next_runner(scheduler: RoundRobinScheduler[MockTask, MockRunner]):
    # Given
    task = MockTask("task1")
    runners = [MockRunner("runner1"), MockRunner("runner2")]
    scheduler.put(task, runners)

    # When
    runner1 = scheduler.get_next_runner(task)
    runner2 = scheduler.get_next_runner(task)
    runner3 = scheduler.get_next_runner(task)

    # Then
    assert runner1, "Runner1 is None"
    assert runner1.id == "runner1"
    assert runner2, "Runner2 is None"
    assert runner2.id == "runner2"
    assert runner3 is None


def test_remove_task(scheduler: RoundRobinScheduler[MockTask, MockRunner]):
    # Given
    task = MockTask("task1")
    runners = [MockRunner("runner1")]
    scheduler.put(task, runners)

    # When
    scheduler.remove_task(task)

    # Then
    assert scheduler.get_next_task() is None
    assert scheduler.get_next_runner(task) is None


def test_empty_scheduler(scheduler: RoundRobinScheduler[MockTask, MockRunner]):
    # When
    next_task = scheduler.get_next_task()
    next_runner = scheduler.get_next_runner(MockTask("task1"))

    # Then
    assert next_task is None
    assert next_runner is None


def test_multiple_tasks_and_runners(
    scheduler: RoundRobinScheduler[MockTask, MockRunner],
):
    # Given
    task1 = MockTask("task1")
    task2 = MockTask("task2")
    runners1 = [MockRunner("runner1"), MockRunner("runner2")]
    runners2 = [MockRunner("runner3"), MockRunner("runner4")]

    # When
    scheduler.put(task1, runners1)
    scheduler.put(task2, runners2)

    # Then
    # First round
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task1"
    next_runner = scheduler.get_next_runner(task1)
    assert next_runner, "Next runner is None"
    assert next_runner.id == "runner1"
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task2"
    next_runner = scheduler.get_next_runner(task2)
    assert next_runner, "Next runner is None"
    assert next_runner.id == "runner3"

    # Second round
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task1"
    next_runner = scheduler.get_next_runner(task1)
    assert next_runner, "Next runner is None"
    assert next_runner.id == "runner2"
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task2"
    next_runner = scheduler.get_next_runner(task2)
    assert next_runner, "Next runner is None"
    assert next_runner.id == "runner4"

    # Third round - runners depleted
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task1"
    assert scheduler.get_next_runner(task1) is None
    next_task = scheduler.get_next_task()
    assert next_task, "Next task is None"
    assert next_task.id == "task2"
    assert scheduler.get_next_runner(task2) is None


def test_remove_task_after_runners_depleted(
    scheduler: RoundRobinScheduler[MockTask, MockRunner],
):
    # Given
    task = MockTask("task1")
    runners = [MockRunner("runner1")]
    scheduler.put(task, runners)

    # When
    runner = scheduler.get_next_runner(task)
    assert runner, "Runner is None"
    assert runner.id == "runner1"

    # Runner depleted
    assert scheduler.get_next_runner(task) is None

    # Remove task
    scheduler.remove_task(task)

    # Then
    assert scheduler.get_next_task() is None
    assert scheduler.get_next_runner(task) is None
