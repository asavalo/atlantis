import psutil
import pytest
from loguru import logger

from sarif.context import SarifCacheManager, SarifServerManager
from sarif.models import CP
from sarif.tools.joern.server import JoernServer


def _check_joern_down(server: JoernServer | None = None):
    processes = psutil.process_iter(["cmdline"])
    for process in processes:
        if process.info["cmdline"] is None:
            continue

        cmdline = " ".join(process.info["cmdline"])

        if server:
            found = (
                "joern" in cmdline
                and str(server.port) in cmdline
                and str(server.cpg_path) in cmdline
            )
        else:
            found = "/usr/bin/local/joern" in cmdline

        if found:
            logger.warning(f"Joern process found: {process.info}")
            return False

    logger.info("No joern process found")
    return True


class TestJoernServer:
    def test_joern_server_stop(self, cp: CP):
        server = SarifServerManager().joern_server

        assert not _check_joern_down()
        assert server.is_running()

        server.stop()

        assert _check_joern_down()
        assert not server.is_running()

    def test_joern_server_cached(self, cp: CP):
        SarifCacheManager().clear()

        logger.info("First server running...")

        server = SarifServerManager(joern_kwargs={"stop_on_exit": False}).joern_server
        first_port = server.port

        # Check if the server is running
        assert server.is_running()
        assert not _check_joern_down(server)

        logger.info("Second server running...")

        server = SarifServerManager(
            joern_kwargs={"stop_on_exit": False}, force_new_instance=True
        ).joern_server
        second_port = server.port

        server.stop()

        assert first_port == second_port
        assert _check_joern_down(server)
