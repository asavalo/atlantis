import os
import logging
import random
import socket
import subprocess
import tempfile
import time
import requests
from pathlib import Path
from typing import Optional

import psutil
from vuli.common.setting import Setting
from vuli.cp import CP


class Debugger:
    def __init__(self, timeout: float = 30.0):
        self._logger = logging.getLogger("Debugger")
        self._client = None
        self._server = None
        self._file = tempfile.NamedTemporaryFile(dir=Setting().tmp_dir)
        self._timeout = timeout

    def run(self, harness_name: str, blob: bytes, cmd: list[str]) -> str:
        if True:
            binary = f"{harness_name}"
            filename = f"{Path(self._file.name).name}"
            breakpoints = cmd 
            dir = f"{CP().source_dir}"

            with Path(self._file.name).open("wb") as f:
                f.write(blob)

            cmd = [ 
                "bash",
                "/app/llm-poc-gen/run_gdb.sh",
                binary,
                filename,
            ] + breakpoints + ["--dir", dir]

            try:
                env = os.environ.copy()
                env["ASAN_OPTIONS"] = "detect_leaks=0"
                env["LSAN_OPTIONS"] = "detect_leaks=0"
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=60,
                    env=env,
                    cwd=CP().built_path
                )

                with open(f"shared/logs/{Path(self._file.name).name}", "r") as log_file:
                    result = log_file.read()
                return result
            except Exception:
                pass

        else:
            port: int = self._assign_port()
            if not self._run_server(blob, harness_name, port):
                return ""
            if True:
                self._run_client(port, harness_name)
                cmd[:0] = [
                    "set logging enabled",
                    "set filename-display absolute",
                    f"target remote localhost:{port}"
                ]
                cmd.extend(["continue"] * 100)
            else:
                self._run_client(port)
                cmd.append("run")
            self._send(f"{"\n".join(cmd)}\n")
            try:
                self._client.wait(self._timeout)
            except subprocess.TimeoutExpired:
                pass
            finally:
                self.stop()

            result: str = self._client.stdout.read()
            return result

    def stop(self) -> None:
        self._terminate_process(self._client)
        self._terminate_process(self._server)
        self._file = None

    def _send(self, cmd: str) -> None:
        try:
            self._client.stdin.write(f"{cmd}\n")
            self._client.stdin.flush()
        except BrokenPipeError:
            pass

    def _run_client(self, port: int, harness_name: str = "") -> None:
        if True:
            cp_root = Setting().cp_root
            harness_path = cp_root / str(CP().get_harness_bin_path(harness_name))
            cmd: list[str] = ["gdb", str(harness_path)]
            cwd = Path(cp_root) / CP().built_path
        else:
            cmd: list[str] = ["jdb", "-attach", f"localhost:{port}"]
            cwd = None
        self._logger.debug(f"Client: {" ".join(cmd)}")
        self._client = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        time.sleep(0.5)

    def _run_server(self, blob: bytes, harness_name: str, port: int) -> bool:
        with Path(self._file.name).open("wb") as f:
            f.write(blob)
        cp_root = Setting().cp_root
        harness_path: str = str(cp_root / CP().get_harness_bin_path(harness_name))
        if len(harness_path) == 0:
            return False
        if True:
            env = os.environ.copy()
            env["ASAN_OPTIONS"] = "detect_leaks=0"
            cmd: list[str] = [
                "gdbserver",
                f":{port}",
                f"{harness_path}",
                "-runs=1",
                f"-timeout={self._timeout}",
                f"{self._file.name}",
            ]
            cwd = Setting().cp_root / CP().built_path
        else:
            harness_path: str = str(CP().get_harness_path(harness_name))
            class_name: str = CP().harnesses.get(harness_name, {}).get("target_class", "")
            cmd: list[str] = [
                "java",
                f"-Dllmpocgen={Setting().root_dir}",
                f"-agentlib:jdwp=transport=dt_socket,server=y,address={port},suspend=y",
                "-cp",
                f"{":".join([x for x in CP().get_jars(harness_path)])}:{Setting().agent_path}",
                "sr.AgentMain",
                class_name,
                self._file.name,
            ]
            cwd, env = None, None
        self._logger.debug(f"Server: {" ".join(cmd)}")
        self._server = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env
        )
        # TODO: Wait until server is ready. 0.5 second may not be enough.
        time.sleep(0.5)
        return True

    # Duplicates: Joern
    def _assign_port(self) -> int:
        while True:
            port = random.randint(10000, 65535)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex(("localhost", port)) != 0:
                    return port

    # Duplicates: Joern
    def _terminate_process(self, process: Optional[subprocess.Popen]) -> None:
        if process is None:
            return

        if process.poll() is not None:
            return

        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        _, still_alive = psutil.wait_procs(children, timeout=3)
        for p in still_alive:
            p.kill()
        process.terminate()
        try:
            process.wait(3)
        except subprocess.TimeoutExpired:
            process.kill()
