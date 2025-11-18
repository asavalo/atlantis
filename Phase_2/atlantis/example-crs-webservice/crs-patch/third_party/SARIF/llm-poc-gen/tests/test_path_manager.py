import pytest
from vuli.path_manager import PathManager
from vuli.scan import Origin, SinkManager, SinkProperty, Status
from vuli.struct import CodeLocation, VulInfo


@pytest.fixture(autouse=True)
def setup():
    SinkManager().clear()
    PathManager().clear()


def test_add_ignore():
    path_1 = VulInfo("harness", 0, [], CodeLocation("path", 0))
    path_2 = VulInfo("harness", 0, [], CodeLocation("path", 0))
    PathManager().add(path_1)
    assert len(PathManager()._table) == 1
    assert len(PathManager()._queue) == 1
    PathManager().add(path_1)
    assert len(PathManager()._table) == 1
    assert len(PathManager()._queue) == 1
    PathManager().add(path_2)
    assert len(PathManager()._table) == 1
    assert len(PathManager()._queue) == 1
    PathManager().get()
    assert len(PathManager()._table) == 1
    assert len(PathManager()._queue) == 0
    PathManager().add(path_1)
    assert len(PathManager()._table) == 1
    assert len(PathManager()._queue) == 0


def test_empty_get():
    assert PathManager().get() is None


def test_get():
    path = VulInfo("harness", 0, [], CodeLocation("path", 0))
    PathManager().add(path)
    assert PathManager().get() == path
    assert PathManager().get() is None


def test_get_multiple():
    path_1 = VulInfo("harness", 0, [], CodeLocation("path_1", 0))
    path_2 = VulInfo("harness", 0, [], CodeLocation("path_2", 0))
    PathManager().add(path_1)
    PathManager().add(path_2)
    assert PathManager().get() == path_1
    assert PathManager().get() == path_2
    assert PathManager().get() is None


def test_get_priority():
    path_1 = VulInfo("harness", 0, [], CodeLocation("path_1", 0))
    path_2 = VulInfo("harness", 1, [], CodeLocation("path_2", 0))
    PathManager().add(path_1)
    PathManager().add(path_2)
    SinkManager().add(
        (
            0,
            SinkProperty(
                bug_types=set(), origins={Origin.FROM_INSIDE}, status=Status.UNKNOWN
            ),
        )
    )
    SinkManager().add(
        (
            1,
            SinkProperty(
                bug_types=set(), origins={Origin.FROM_SARIF}, status=Status.UNKNOWN
            ),
        )
    )
    assert PathManager().get() == path_2
    assert PathManager().get() == path_1
    assert PathManager().get() is None


def test_get_harness_balance():
    path_1 = VulInfo("harness_1", 0, [], CodeLocation("path_1", 0))
    path_2 = VulInfo("harness_1", 1, [], CodeLocation("path_2", 0))
    path_3 = VulInfo("harness_2", 2, [], CodeLocation("path_3", 0))
    PathManager().add(path_1)
    PathManager().add(path_2)
    PathManager().add(path_3)
    assert PathManager().get() == path_1
    assert PathManager().get() == path_3
    assert PathManager().get() == path_2
    assert PathManager().get() is None


def test_get_harness_balance_and_priority():
    path_1 = VulInfo("harness_1", 0, [], CodeLocation("path_1", 0))
    path_2 = VulInfo("harness_1", 1, [], CodeLocation("path_2", 0))
    path_3 = VulInfo("harness_2", 2, [], CodeLocation("path_3", 0))
    PathManager().add(path_1)
    PathManager().add(path_2)
    PathManager().add(path_3)
    SinkManager().add(
        (
            0,
            SinkProperty(
                bug_types=set(), origins={Origin.FROM_SARIF}, status=Status.UNKNOWN
            ),
        )
    )
    SinkManager().add(
        (
            1,
            SinkProperty(
                bug_types=set(), origins={Origin.FROM_SARIF}, status=Status.UNKNOWN
            ),
        )
    )
    SinkManager().add(
        (
            2,
            SinkProperty(
                bug_types=set(), origins={Origin.FROM_INSIDE}, status=Status.UNKNOWN
            ),
        )
    )
    assert PathManager().get() == path_1
    assert PathManager().get() == path_2
    assert PathManager().get() == path_3
    assert PathManager().get() is None
