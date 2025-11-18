import pytest

from scripts.benchmark.functions import execute_in_process


@pytest.mark.timeout(1)
def test_execute_in_process_raise_error():
    def _raise_error():
        raise Exception("Test exception")

    try:
        execute_in_process(_raise_error, ())
        pytest.fail("Should raise an exception")
    except Exception as e:
        assert str(e) == "Test exception"


@pytest.mark.timeout(10)
def test_execute_in_process_hang():
    def _infinite_loop():
        while True:
            pass

    try:
        execute_in_process(_infinite_loop, (), timeout=1)
        pytest.fail("Should raise an exception")
    except TimeoutError:
        pass
