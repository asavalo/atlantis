import asyncio
from typing import Callable
from unittest.mock import patch

import pytest
import requests
from pydantic import BaseModel
from vuli.runner import CRS, Runner
from vuli.scan import Origin, SinkManager, SinkProperty, Status

counter: int = 0


class FakeResponse(BaseModel):
    status_code: int
    response: dict

    def json(self) -> dict:
        return self.response


@pytest.mark.timeout(5)
@patch("vuli.runner.Runner._generate_blob")
def test_run_without_server(mock_generate_blob):
    global counter
    counter = 0
    org: Callable = requests.get

    def return_generate_blob(*args, **kwargs):
        return

    mock_generate_blob.side_effect = return_generate_blob

    def return_requests(*args, **kwargs):
        global counter
        if counter < 3:
            counter += 1
            return org(args, kwargs)
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    with patch("requests.get") as mock:
        mock.side_effect = return_requests
        runner: Runner = CRS(period=1)
        try:
            asyncio.run(runner._run())
        except Exception:
            pytest.fail("CRS Runner MUST never throw exception")


@pytest.mark.timeout(5)
@patch("requests.get")
@patch("vuli.runner.Runner._generate_blob")
def test_invalid_response(mock_generate_blob, mock_requests):
    global counter
    counter = 0

    def return_generate_blob(*args, **kwargs):
        return None

    def return_requests(*args, **kwargs):
        global counter
        if counter == 0:
            counter += 1
            return FakeResponse(status_code=200, response={})
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    mock_generate_blob.side_effect = return_generate_blob
    mock_requests.side_effect = return_requests

    runner: Runner = CRS(period=1)
    try:
        asyncio.run(runner._run())
    except Exception:
        pytest.fail("CRS Runner MUST never throw exception")


@pytest.mark.timeout(10)
@patch("requests.get")
@patch("vuli.runner.Runner._generate_blob")
def test_invalid_sarif_response(mock_generate_blob, mock_requests):
    global counter
    counter = 0

    def return_generate_blob(*args, **kwargs):
        return None

    def return_requests(*args, **kwargs):
        global counter
        if counter == 0:
            counter += 1
            return FakeResponse(status_code=200, response={"command": "sarif"})
        elif counter == 1:
            counter += 1
            return FakeResponse(
                status_code=200, response={"command": "sarif", "file_path": "tmp"}
            )
        elif counter == 2:
            counter += 1
            return FakeResponse(
                status_code=200, response={"command": "sarif", "line_number": 10}
            )
        elif counter == 3:
            counter += 1
            return FakeResponse(
                status_code=200, response={"command": "sarif", "file_path": None}
            )
        elif counter == 4:
            counter += 1
            return FakeResponse(
                status_code=200, response={"command": "sarif", "line_number": "unknown"}
            )
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    mock_generate_blob.side_effect = return_generate_blob
    mock_requests.side_effect = return_requests
    runner: Runner = CRS(period=1)
    try:
        asyncio.run(runner._run())
    except Exception:
        pytest.fail("CRS Runner MUST never throw exception")


@pytest.mark.timeout(5)
@patch("requests.get")
@patch("vuli.runner.Runner._generate_blob")
@patch("vuli.joern.Joern.run_query")
def test_handle_sarif_new_call(mock_joern, mock_generate_blob, mock_requests):
    global counter
    counter = 0
    SinkManager().clear()

    def return_joern(*args, **kwargs):
        return {"calls": [0], "args": [], "firsts": []}

    def return_generate_blob(*args, **kwargs):
        return None

    def return_requests(*args, **kwargs):
        global counter
        if counter == 0:
            counter += 1
            return FakeResponse(
                status_code=200,
                response={"command": "sarif", "file_path": "test", "line_number": 10},
            )
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    mock_joern.side_effect = return_joern
    mock_generate_blob.side_effect = return_generate_blob
    mock_requests.side_effect = return_requests
    runner: Runner = CRS(period=1)
    try:
        asyncio.run(runner._run())
    except Exception:
        pytest.fail("CRS Runner MUST never throw exception")

    sinks: dict = SinkManager().get()
    assert 0 in sinks
    assert sinks[0] == SinkProperty(
        bug_types=set(), origins={Origin.FROM_SARIF}, status=Status.UNKNOWN
    )


@pytest.mark.timeout(15)
@patch("requests.get")
@patch("vuli.runner.Runner._generate_blob")
@patch("vuli.joern.Joern.run_query")
def test_handle_sarif_new_arg(mock_joern, mock_generate_blob, mock_requests):
    global counter
    counter = 0
    SinkManager().clear()

    def return_joern(*args, **kwargs):
        return {"calls": [], "args": [1], "firsts": []}

    def return_generate_blob(*args, **kwargs):
        return None

    def return_requests(*args, **kwargs):
        global counter
        if counter == 0:
            counter += 1
            return FakeResponse(
                status_code=200,
                response={"command": "sarif", "file_path": "test", "line_number": 10},
            )
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    mock_joern.side_effect = return_joern
    mock_generate_blob.side_effect = return_generate_blob
    mock_requests.side_effect = return_requests
    runner: Runner = CRS(period=1)
    try:
        asyncio.run(runner._run())
    except Exception:
        pytest.fail("CRS Runner MUST never throw exception")

    sinks: dict = SinkManager().get()
    assert 1 in sinks
    assert sinks[1] == SinkProperty(
        bug_types=set(), origins={Origin.FROM_SARIF}, status=Status.UNKNOWN
    )


@pytest.mark.timeout(15)
@patch("requests.get")
@patch("vuli.runner.Runner._generate_blob")
@patch("vuli.joern.Joern.run_query")
def test_handle_sarif_new_entry(mock_joern, mock_generate_blob, mock_requests):
    global counter
    counter = 0
    SinkManager().clear()

    def return_joern(*args, **kwargs):
        return {"calls": [], "args": [], "firsts": [2]}

    def return_generate_blob(*args, **kwargs):
        return None

    def return_requests(*args, **kwargs):
        global counter
        if counter == 0:
            counter += 1
            return FakeResponse(
                status_code=200,
                response={"command": "sarif", "file_path": "test", "line_number": 10},
            )
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    mock_joern.side_effect = return_joern
    mock_generate_blob.side_effect = return_generate_blob
    mock_requests.side_effect = return_requests
    runner: Runner = CRS(period=1)
    try:
        asyncio.run(runner._run())
    except Exception:
        pytest.fail("CRS Runner MUST never throw exception")

    sinks: dict = SinkManager().get()
    assert 2 in sinks
    assert sinks[2] == SinkProperty(
        bug_types=set(), origins={Origin.FROM_SARIF}, status=Status.UNKNOWN
    )


@pytest.mark.timeout(15)
@patch("requests.get")
@patch("vuli.runner.Runner._generate_blob")
@patch("vuli.joern.Joern.run_query")
def test_handle_sarif_update(mock_joern, mock_generate_blob, mock_requests):
    global counter
    counter = 0
    SinkManager().clear()
    SinkManager().add(
        (
            4,
            SinkProperty(
                bug_types=set(),
                origins={Origin.FROM_INSIDE},
                status=Status.MAY_REACHABLE,
            ),
        )
    )

    def return_joern(*args, **kwargs):
        return {"calls": [4], "args": [5], "firsts": [6]}

    def return_generate_blob(*args, **kwargs):
        return None

    def return_requests(*args, **kwargs):
        global counter
        if counter == 0:
            counter += 1
            return FakeResponse(
                status_code=200,
                response={"command": "sarif", "file_path": "test", "line_number": 10},
            )
        else:
            return FakeResponse(status_code=200, response={"command": "quit"})

    mock_joern.side_effect = return_joern
    mock_generate_blob.side_effect = return_generate_blob
    mock_requests.side_effect = return_requests
    runner: Runner = CRS(period=1)
    try:
        asyncio.run(runner._run())
    except Exception:
        pytest.fail("CRS Runner MUST never throw exception")

    sinks: dict = SinkManager().get()
    assert 4 in sinks
    assert sinks[4] == SinkProperty(
        bug_types=set(),
        origins={Origin.FROM_INSIDE, Origin.FROM_SARIF},
        status=Status.MAY_REACHABLE,
    )
