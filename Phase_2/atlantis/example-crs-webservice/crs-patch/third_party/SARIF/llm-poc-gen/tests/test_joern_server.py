import os
import unittest
from unittest.mock import patch

from vuli.joern import JoernServer


def is_valid_query(res):
    query_response = res[0]
    query_result = res[1]
    return (
        True
        if (
            query_result is True
            and query_response.get("stdout") is not None
            and not query_response["stdout"].endswith("error found\n")
        )
        else False
    )


@unittest.skipIf(
    not os.getenv("JOERN_DIR"), "JOERN_DIR environment variable is not set"
)
class TestJoernServer(unittest.TestCase):
    def setUp(self):
        self.joern_server = JoernServer(
            os.path.join(os.getenv("JOERN_DIR"), "joern"), os.environ.copy()
        )
        self.joern_server.start()

    def tearDown(self) -> None:
        self.joern_server.stop()

    def test_timeout_and_query(self):
        self.assertFalse(
            is_valid_query(self.joern_server.query("Thread.sleep(10000)", timeout=1))
        )
        self.assertTrue(is_valid_query(self.joern_server.query("")))

    @patch("vuli.joern.JoernServer.restart")
    def test_query_intime(self, restart):
        self.assertTrue(
            is_valid_query(self.joern_server.query("Thread.sleep(1000)", timeout=10))
        )
        self.assertFalse(restart.called)

    @patch("vuli.joern.JoernServer.restart")
    def test_query_timeout(self, restart):
        self.assertFalse(
            is_valid_query(self.joern_server.query("Thread.sleep(10000)", timeout=1))
        )
        restart.assert_called_once()

    @patch("vuli.joern.JoernServer.restart")
    def test_query_no_restart_on_failure(self, restart):
        self.assertFalse(
            is_valid_query(
                self.joern_server.query(
                    "Thread.sleep(10000)", timeout=1, restart_on_failure=False
                )
            )
        )
        self.assertFalse(restart.called)

    def test_query_invalid(self):
        self.assertFalse(is_valid_query(self.joern_server.query("invalid")))

    def test_query_stopped_server(self):
        self.joern_server.stop()
        self.assertFalse(is_valid_query(self.joern_server.query("")))

    def test_restart(self):
        self.joern_server.restart()
        self.assertTrue(is_valid_query(self.joern_server.query("")))

    def test_start_twice(self):
        self.joern_server.start()
        self.joern_server.start()
        self.assertTrue(is_valid_query(self.joern_server.query("")))

    def test_restart_twice(self):
        self.joern_server.restart()
        self.joern_server.restart()
        self.assertTrue(is_valid_query(self.joern_server.query("")))

    def test_stop_twice(self):
        self.joern_server.stop()
        self.joern_server.stop()


@unittest.skipIf(not os.getenv("JOERN_DIR"), "JOERN environment variable is not set")
class TestJoernServerWithScript(unittest.TestCase):
    def setUp(self):
        self.joern_server = JoernServer(
            os.path.join(os.getenv("JOERN_DIR"), "joern"),
            os.environ.copy(),
            ["val a = 1"],
        )
        self.joern_server.start()

    def tearDown(self) -> None:
        self.joern_server.stop()

    def test_init_script_defined(self):
        res = self.joern_server.query("val b = a")
        self.assertTrue(is_valid_query(res))
        res = self.joern_server.query("val c = b")
        self.assertTrue(is_valid_query(res))

    def test_init_script_undefined(self):
        res = self.joern_server.query("val c = b")
        self.assertFalse(is_valid_query(res))


@unittest.skipIf(not os.getenv("JOERN_DIR"), "JOERN environment variable is not set")
class StressTestJoernServer(unittest.TestCase):
    def setUp(self):
        self.joern_server = JoernServer(
            os.path.join(os.getenv("JOERN_DIR"), "joern"), os.environ.copy()
        )
        self.joern_server.start()

    def tearDown(self) -> None:
        self.joern_server.stop()

    @patch("vuli.joern.JoernServer.restart")
    def test_timeout_10sec(self, restart):
        res = self.joern_server.query(
            "val largeArray: Array[Int] = Array.fill(1000000000)(0)", timeout=10
        )
        self.assertFalse(is_valid_query(res))
        self.assertTrue(restart.called)

    @patch("vuli.joern.JoernServer.restart")
    def test_timeout_60sec(self, restart):
        res = self.joern_server.query(
            "val largeArray: Array[Int] = Array.fill(1000000000)(0)", timeout=60
        )
        self.assertFalse(is_valid_query(res))
        self.assertTrue(restart.called)
