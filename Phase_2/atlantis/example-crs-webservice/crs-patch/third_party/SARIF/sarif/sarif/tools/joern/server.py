import atexit
import json
import os
import random
import socket
import subprocess
import time

import psutil
import requests
from loguru import logger

from sarif.context import SarifCacheManager
from sarif.utils.cache import cache_method_with_attrs


class JoernServer:
    def __init__(self, cpg_path: str, timeout=3600, memory=12, stop_on_exit=False):
        self.__cpg_path = cpg_path
        self.__timeout = timeout
        self.__port = None
        self.__url = None
        self.__server = None
        self.__memory = memory
        self.__server_run_datetime = time.time()

        if stop_on_exit:
            atexit.register(self.stop)

        self.start()

    @property
    def cpg_path(self):
        return self.__cpg_path

    @property
    def port(self):
        return self.__port

    def query(self, script, timeout=-1, restart_on_failure=True) -> tuple[dict, bool]:
        if not self.is_running():
            logger.warning("Failed to query to stopped joern server")
            return ({}, True)
        data = {"query": script}
        timeout = timeout if timeout > 0 else self.__timeout if timeout < 0 else None
        try:
            res = requests.post(self.__url, json=data, timeout=timeout)
            if res.status_code == 200:
                return (res.json(), True)
        except requests.Timeout:
            if restart_on_failure:
                logger.warning(f" - Joern server query timeout({timeout})")
                self.restart()
                return ({}, False)
        except requests.exceptions.RequestException:
            if restart_on_failure:
                logger.warning(f" - Joern server query RequestException")
                self.restart()
                return ({}, True)
        return ({}, True)

    def query_json(self, script, timeout=-1, restart_on_failure=True) -> dict:
        res, valid = self.query(script, timeout, restart_on_failure)

        if not valid:
            return dict()

        stdout = res.get("stdout", "")
        raw_result = stdout[stdout.find("= ") + 1 :]
        if raw_result.startswith('"""'):
            raw_result = "r" + raw_result

        try:
            parsed = json.loads(eval(raw_result))
        except:
            parsed = dict()

        return parsed

    def is_running(self) -> bool:
        return self.__server != None

    def stop(self):
        if not self.is_running():
            logger.warning(" - Joern server is already stopped")
            return
        if isinstance(self.__server, str) and self.__server == "cached":
            logger.warning(" - Joern server is cached. Killing all joern servers")
            try:
                JoernServer._kill_all_joern_servers()
            except Exception:
                logger.warning(
                    " - Failed to kill all joern servers. Please kill manually"
                )
        else:
            try:
                logger.warning(" - Joern server stop...")
                parent = psutil.Process(self.__server.pid)
                children = parent.children(recursive=True)
                for child in children:
                    child.terminate()
                _, still_alive = psutil.wait_procs(children, timeout=3)
                for p in still_alive:
                    p.kill()
                self.__server.terminate()
                self.__server.wait(3)
            except Exception:
                logger.warning(" - Joern server kill...")
                self.__server.kill()
        self.__server = None

    def restart(self):
        self.stop()
        self.start()

    def _is_startswith_condition_preprocessor(self, line: str) -> bool:
        strip_preprocess_conditions = [
            "#if",
            "#elif",
            "#else",
            "#endif",
            "#ifdef",
            "#ifndef",
            "#elifdef",
            "#elifndef",
            "#endif",
        ]
        for preprocess_condition in strip_preprocess_conditions:
            if line.lstrip().startswith("#") and line[1:].lstrip().startswith(
                preprocess_condition[1:]
            ):
                return True
        return False

    @staticmethod
    def _is_port_in_use(port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("localhost", port)) != 0:
                return False
            else:
                return True

    def _check_joern_running(self) -> bool:
        processes = psutil.process_iter(["cmdline"])
        for process in processes:
            if process.info["cmdline"] is None:
                continue

            cmdline = " ".join(process.info["cmdline"])

            if (
                "joern" in cmdline
                and str(self.port) in cmdline
                and str(self.cpg_path) in cmdline
            ):
                logger.info(f"Joern process found: {process.info}")
                return True

        logger.warning("No joern process found")
        return False

    @cache_method_with_attrs(
        mem=SarifCacheManager().memory, attr_names=["_JoernServer__cpg_path"]
    )
    def _assign_port(self):
        while True:
            port = random.randint(10000, 65535)
            if not JoernServer._is_port_in_use(port):
                return (port, self.__server_run_datetime)

    @staticmethod
    def _find_all_joern_processes():
        processes = psutil.process_iter(["cmdline"])
        for process in processes:
            if process.info["cmdline"] is None:
                continue

            cmdline = " ".join(process.info["cmdline"])

            if "joern --server --server-port" in cmdline:
                yield process

    # ! Should be dangerous??
    @staticmethod
    def _kill_all_joern_servers():
        try:

            def _kill_proc(process: psutil.Process):
                process.terminate()
                process.wait(timeout=3)
                if process.is_running():
                    process.kill()

            all_joern_processes = list(JoernServer._find_all_joern_processes())

            for process in all_joern_processes:
                for child in process.children(recursive=True):
                    _kill_proc(child)
                _kill_proc(process)
        except Exception:
            logger.warning("Failed to kill all joern servers")

    def _check_joern(self) -> bool:
        try:
            res, valid = self.query("cpg.method.size", restart_on_failure=False)

            if not valid:
                logger.warning("Joern check query failed validation.")
                return False

            if not (isinstance(res, dict) and res.get("success") is True):
                logger.warning(f"Joern check query was not successful: {res}")
                return False

            stdout = res.get("stdout")
            if not stdout:
                logger.warning(f"Joern check query missing stdout: {res}")
                return False

            size_str = stdout.split("= ")[-1].strip()
            method_size = int(size_str)

            logger.info(f"Joern check found method size: {method_size}")
            is_ok = method_size >= 1
            if not is_ok:
                logger.warning(f"Joern check found method size < 1: {method_size}")
            return is_ok

        except (ValueError, IndexError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse joern check result: {e}. Response: {res}")
            return False
        except Exception as e:
            logger.error(f"An unexpected error occurred during joern check: {e}")
            return False

    def start(self):
        def __run() -> None:
            cmd = [
                "/opt/joern/joern-cli/target/universal/stage/joern",
                "--server",
                "--server-port",
                f"{self.__port}",
                "--nocolors",
                f"{self.__cpg_path}",
            ]
            env = os.environ.copy()
            env["JAVA_OPTS"] = (
                f"-Xmx{self.__memory}G -XX:ParallelGCThreads=8 -XX:ConcGCThreads=4 -Djava.util.concurrent.ForkJoinPool.common.parallelism=20"
            )
            self.__server = subprocess.Popen(
                cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            retry = 60
            while retry > 0:
                try:
                    logger.info("Joern server is starting...")
                    res = self.query("", restart_on_failure=False)[0]
                    if (
                        isinstance(res, dict)
                        and "success" in res
                        and res["success"] == True
                    ):
                        if self._check_joern():
                            return
                        else:
                            logger.error("Joern server check failed")
                            return
                except Exception:
                    pass
                retry -= 1
                time.sleep(1)

            logger.error("Failed to start joern server")

            self.stop()

        if self.is_running():
            self.stop()

        self.__port, server_run_datetime = self._assign_port()
        self.__url = f"http://localhost:{self.__port}/query-sync"
        if server_run_datetime == self.__server_run_datetime:
            # new server run
            JoernServer._kill_all_joern_servers()
            __run()
        else:
            # cached server run
            logger.info(f"Joern port {self.__port} is cached")

            if not self._check_joern_running():
                logger.debug(
                    f"Joern port {self.__port} is cached but server is not running. starting joern server"
                )
                __run()
            else:
                self.__server = "cached"
