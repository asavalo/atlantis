import asyncio
import time
from unittest.mock import patch

import pytest
from vuli import path_manager
from vuli.calltree import CallTree
from vuli.common.setting import Setting
from vuli.cp import CP
from vuli.pathfinder import PathFinder
from vuli.runner import CRS, Runner
from vuli.scan import SinkManager, SinkProperty, Status
from vuli.struct import CodeLocation, VulInfo

allow: set[int] = set()


@pytest.fixture(autouse=True)
def setup():
    global allow
    SinkManager().clear()
    path_manager.PathManager().clear()
    CP().harnesses = {}
    allow = set()


@pytest.mark.asyncio
@patch.object(PathFinder, "find")
async def test_sink_to_path(mock) -> None:
    global allow

    SinkManager().add((0, SinkProperty(bug_types=set(), origins=set())))
    SinkManager().add((1, SinkProperty(bug_types=set(), origins=set())))
    SinkManager().add((2, SinkProperty(bug_types=set(), origins=set())))
    CP().harnesses = {"h1": {}}

    def mock_effect(harness_name: str, sinks: set[int]) -> list[VulInfo]:
        find: set[int] = sinks & allow
        return [VulInfo(harness_name, x, [], CodeLocation("", 0, 0)) for x in find]

    async def controller(runner: Runner) -> None:
        global allow

        async def wait(key: int):
            while True:
                await asyncio.sleep(1)
                if 0 not in SinkManager().get():
                    continue
                if not SinkManager().get()[0].status == Status.MAY_REACHABLE:
                    continue
                break

        allow = set({0})
        CallTree()._updated = True
        await wait(0)

        assert (
            0 in SinkManager().get()
            and SinkManager().get()[0].status == Status.MAY_REACHABLE
            and 1 in SinkManager().get()
            and SinkManager().get()[1].status == Status.MAY_UNREACHABLE
            and 2 in SinkManager().get()
            and SinkManager().get()[2].status == Status.MAY_UNREACHABLE
        )

        allow = set({1})
        CallTree()._updated = True
        await wait(1)

        assert (
            0 in SinkManager().get()
            and SinkManager().get()[0].status == Status.MAY_REACHABLE
            and 1 in SinkManager().get()
            and SinkManager().get()[1].status == Status.MAY_REACHABLE
            and 2 in SinkManager().get()
            and SinkManager().get()[2].status == Status.MAY_UNREACHABLE
        )

        runner._stop_sink_to_path = True

    mock.side_effect = mock_effect
    runner: Runner = CRS()
    tasks = [runner.sink_to_path(), controller(runner)]
    await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)


class MockRunner(Runner):
    def __init__(self, max_workers: int = 1, delay: int = 0):
        super().__init__(max_workers)
        self._delay: int = delay

    async def _run(self) -> None:
        await self._generate_blob()

    def _to_task(self, harness_id: str, path: VulInfo) -> dict:
        return {"candidate:": path, "harness_id": harness_id}

    def _generate_seed(self, task: dict) -> dict:
        time.sleep(self._delay)
        task["reached"] = True
        return task

    def _generate_pov(self, task: dict) -> dict:
        time.sleep(self._delay)
        task["crash"] = True
        return task


@pytest.mark.asyncio
async def test_blob_generation():
    runner: Runner = MockRunner()
    Setting().dev = False
    path: VulInfo = VulInfo("harness_1", 1, [], CodeLocation("path_1", 1, 1))
    path_manager.PathManager().add(path)
    runner._stop_generation_if_no_path = True
    await runner._run()
    assert (
        path_manager.PathManager().get_status(path) == path_manager.Status.EXPLOITABLE
    )


@pytest.mark.asyncio
async def test_blob_generation_multiple():
    runner: Runner = MockRunner()
    Setting().dev = False
    path_1: VulInfo = VulInfo("harness_1", 1, [], CodeLocation("path_1", 1, 1))
    path_2: VulInfo = VulInfo("harness_1", 2, [], CodeLocation("path_1", 2, 2))
    path_manager.PathManager().add(path_1)
    path_manager.PathManager().add(path_2)
    runner._stop_generation_if_no_path = True
    await runner._run()
    assert (
        path_manager.PathManager().get_status(path_1) == path_manager.Status.EXPLOITABLE
    )
    assert (
        path_manager.PathManager().get_status(path_2) == path_manager.Status.EXPLOITABLE
    )


@pytest.mark.asyncio
async def test_blob_generation_multiple_in_parallel():
    runner: Runner = MockRunner(max_workers=2, delay=1)
    Setting().dev = False
    path_1: VulInfo = VulInfo("harness_1", 1, [], CodeLocation("path_1", 1, 1))
    path_2: VulInfo = VulInfo("harness_1", 2, [], CodeLocation("path_1", 2, 2))
    path_manager.PathManager().add(path_1)
    path_manager.PathManager().add(path_2)
    runner._stop_generation_if_no_path = True
    await runner._run()
    assert (
        path_manager.PathManager().get_status(path_1) == path_manager.Status.EXPLOITABLE
    )
    assert (
        path_manager.PathManager().get_status(path_2) == path_manager.Status.EXPLOITABLE
    )


@pytest.mark.asyncio
async def test_blob_generation_over_in_parallel():
    runner: Runner = MockRunner(max_workers=2, delay=1)
    Setting().dev = False
    path_1: VulInfo = VulInfo("harness_1", 1, [], CodeLocation("path_1", 1, 1))
    path_2: VulInfo = VulInfo("harness_1", 2, [], CodeLocation("path_1", 2, 2))
    path_3: VulInfo = VulInfo("harness_1", 3, [], CodeLocation("path_1", 3, 2))
    path_4: VulInfo = VulInfo("harness_1", 4, [], CodeLocation("path_1", 4, 2))
    path_5: VulInfo = VulInfo("harness_1", 5, [], CodeLocation("path_1", 5, 2))
    path_manager.PathManager().add(path_1)
    path_manager.PathManager().add(path_2)
    path_manager.PathManager().add(path_3)
    path_manager.PathManager().add(path_4)
    path_manager.PathManager().add(path_5)
    runner._stop_generation_if_no_path = True
    await runner._run()
    assert (
        path_manager.PathManager().get_status(path_1) == path_manager.Status.EXPLOITABLE
    )
    assert (
        path_manager.PathManager().get_status(path_2) == path_manager.Status.EXPLOITABLE
    )
    assert (
        path_manager.PathManager().get_status(path_3) == path_manager.Status.EXPLOITABLE
    )
    assert (
        path_manager.PathManager().get_status(path_4) == path_manager.Status.EXPLOITABLE
    )
    assert (
        path_manager.PathManager().get_status(path_5) == path_manager.Status.EXPLOITABLE
    )
