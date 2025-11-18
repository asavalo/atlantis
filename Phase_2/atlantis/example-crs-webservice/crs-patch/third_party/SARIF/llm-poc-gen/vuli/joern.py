import json
import logging
import os
import random
import re
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

import psutil
import requests
from vuli.common.decorators import consume_exc_method
from vuli.common.setting import Setting
from vuli.common.singleton import Singleton

logger = logging.getLogger("vuli")


def to_joern_signature(bytecode_method_signature: str) -> Optional[str]:
    """
    Transform bytecode method signature to joern method signature

    Args:
        bytecode_method_signature (str): Bytecode method signature

    Returns:
        str: joern method signature
    """

    def convert_params(params_str: str):
        """
        Transform bytecode parameters to joern parameters.

        Args:
            params_str (str): Bytecode parameters

        Returns:
            str: Joern parameters.
        """
        if not params_str:
            return ""

        params = []
        i = 0
        while i < len(params_str):
            if params_str[i] == "L":
                end = params_str.index(";", i)
                params.append(to_joern_type(params_str[i : end + 1]))
                i = end + 1
            else:
                params.append(to_joern_type(params_str[i]))
                i += 1
        return ", ".join(params)

    joern_signature: str = bytecode_method_signature.replace("/", ".")
    match: Any = re.match(r"^(.*)\.([^(\s]+)\((.*)\)(.*)$", joern_signature)
    if not match:
        return None

    class_name: str = match.group(1)
    method_name: str = match.group(2)
    params_str: str = match.group(3)
    return_type_bytecode: str = match.group(4)
    return_type_joern: str = to_joern_type(return_type_bytecode)
    params_joern_str = convert_params(params_str)
    return f"{class_name}.{method_name}:{return_type_joern}({params_joern_str})"


def to_joern_type(bytecode_type: str):
    """
    Transform bytecode type to joern type

    Args:
        bytecode_type (str): Bytecode type

    Returns:
        str: Joern type
    """

    if bytecode_type.startswith("L") and bytecode_type.endswith(";"):
        return bytecode_type[1:-1].replace("/", ".")
    elif bytecode_type == "V":
        return "void"
    elif bytecode_type == "I":
        return "int"
    elif bytecode_type == "Z":
        return "boolean"
    elif bytecode_type == "B":
        return "byte"
    elif bytecode_type == "C":
        return "char"
    elif bytecode_type == "D":
        return "double"
    elif bytecode_type == "F":
        return "float"
    elif bytecode_type == "J":
        return "long"
    elif bytecode_type == "S":
        return "short"
    else:
        return bytecode_type


class CPG:
    def __init__(self, path: Path):
        self.path = path
        if self.path.is_dir():
            raise RuntimeError("The directory exists for CPG path.")

    def build(
        self,
        tool: Path,
        source: Path,
        exclude_dirs: list[str],
        dependent_jars: list[str],
    ) -> None:
        cmd: list[str] = [str(tool)]
        if len(exclude_dirs) > 0:
            cmd += ["--exclude", ",".join(exclude_dirs)]
        if len(dependent_jars) > 0:
            cmd += ["--inference-jar-paths", ",".join(dependent_jars)]
        cmd += ["-o", str(self.path), str(source)]
        env = os.environ.copy()
        env["JAVA_OPTS"] = "-Xmx12G"
        logger.debug(f"Command for CPG Building: {' '.join(cmd)}")
        res = subprocess.run(cmd, capture_output=True, env=env)
        # TODO: The following condition cannot catch the exception that occurred
        # during the execution of the above command. Additional error handling
        # will be required in the future.
        if res.returncode != 0:
            raise RuntimeError("CPG Build Failed")


class JoernServer:
    __memory: int = 12

    def __init__(
        self, joern, env, init_scripts=None, timeout=30, memory=12, init_timeout=600
    ):
        default_init_script: str = """import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths, StandardOpenOption}
import org.json4s._
import org.json4s.native.JsonMethods._
import org.json4s.native.Serialization
import org.json4s.native.Serialization.writePretty
import org.json4s.JsonDSL._
def save_as_json(reports: Any, path: String): Unit = {
    implicit val formats: Formats = Serialization.formats(NoTypeHints)
    Files.write(
        Paths.get(path),
        writePretty(reports).getBytes(StandardCharsets.UTF_8),
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING
    )
}
def check_final(x: CfgNode): Boolean = {
    val args = x.fieldAccess.argument.l
    if (args.size != 2) return false
    if (!args(0).isIdentifier || !args(1).isFieldIdentifier) return false
    val class_name = args(0).asInstanceOf[Identifier].typeFullName
    val member_name = args(1).asInstanceOf[FieldIdentifier].canonicalName
    cpg.typeDecl.fullNameExact(class_name).member.nameExact(member_name).where(_.modifier.modifierTypeExact("FINAL")).size > 0
}
def check_constant(x: CfgNode): Boolean = {
    if (x.isLiteral) return true
    if (check_final(x)) return true
    if (x.isCall) {
        val y = x.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
        return y.argument.l.forall(check_constant)
    }
    false
}"""
        self._logger = logging.getLogger("JoernServer")
        self.joern = joern
        self.env = env
        self.__init_scripts = [default_init_script] + (
            init_scripts if init_scripts else []
        )
        self.__timeout = timeout
        self.__init_timeout = init_timeout
        self.__port = None
        self.__url = None
        self.__server = None
        self.__memory = memory
        self._lock = threading.Lock()
        self._cpg: Optional[CPG] = None

    def set_cpg(self, cpg: CPG) -> None:
        self._cpg = cpg
        self._import_cpg(self._cpg.path)

    def query_once(self, script: str, timeout: int = 120) -> str:
        self._logger.debug(f"query: {script}")
        res = self._raw_request(script, timeout)
        return res.text

    def safe_query(self, script: str, timeout: int = 120) -> str:
        retry_flag: bool = True
        self._logger.debug(f"query: {script}")
        while True:
            try:
                res = self._raw_request(script, timeout)
                self._logger.debug(f"result: {res.text}")
                if "Recursion limit exceeded" in res.text:
                    raise RuntimeError("Recursion limit exceeded")
                return res.text
            except Exception as e:
                self._logger.warning(f"Joern Error: {e}")
                self.restart()
                if not retry_flag:
                    raise e
                retry_flag = False

    def _raw_request(self, script: str, timeout: int):
        with self._lock:
            return requests.post(self.__url, json={"query": script}, timeout=timeout)

    @consume_exc_method(default=({}, False))
    def query(self, script, timeout=-1, restart_on_failure=True) -> tuple[dict, bool]:
        if not self.is_running():
            logger.warning("Failed to query to stopped joern server")
            return ({}, True)
        timeout = timeout if timeout > 0 else self.__timeout if timeout < 0 else None
        try:
            self._logger.debug(f"query: {script}")
            res = self._raw_request(script, timeout)
            self._logger.debug(f"result: {res.text}")
            if res.status_code == 200:
                return (res.json(), True)
        except requests.Timeout:
            if restart_on_failure:
                logger.warning(f" - Joern server query timeout({timeout})")
                self.restart()
                return ({}, False)
        except requests.exceptions.RequestException:
            if restart_on_failure:
                logger.warning(" - Joern server query RequestException")
                self.restart()
                return ({}, True)
        return ({}, True)

    def is_running(self) -> bool:
        return self.__server is not None

    def stop(self) -> None:
        if not self.is_running():
            logger.warning(" - Joern server is already stopped")
            return
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

    def restart(self) -> bool:
        self.stop()
        if not self.start():
            logger.error("Joern server restart failed....")
            return False
        if self._cpg:
            self._import_cpg(self._cpg.path)
        logger.info("Server restarted")
        return True

    def start(self) -> bool:
        if self.is_running():
            self.stop()

        self.__port = self._assign_port()
        self.__url = f"http://localhost:{self.__port}/query-sync"
        if not self._run():
            return False
        try:
            for n, init_script in enumerate(self.__init_scripts):
                self.query(
                    init_script,
                    timeout=self.__init_timeout,
                    restart_on_failure=False,
                )
            return True
        except Exception:
            logger.warning(" - Joern server failed init script")
            self.stop()
            return False

    def _assign_port(self):
        while True:
            port = random.randint(10000, 65535)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                if sock.connect_ex(("localhost", port)) != 0:
                    return port

    def _import_cpg(self, cpg_path: Path, retry: int = 5) -> None:
        """
        Load CPG into current joern session.
        Note:
            Some times, importing CPG failed under resource over-used
            environment. To handle this case, this function will include re-try
            mechanism to import CPG. No doubt about whether CPG is built
            correctly within this function.

        Args:
            cpg_path: Path = The path to cpg

        Raises:
            RuntimeError: When failed to import CPG
        """

        def is_imported(response: dict) -> bool:
            return "[io.shiftleft.codepropertygraph.Cpg] = None" not in response.get(
                "stdout", ""
            )

        joern_query: str = f"""importCpg("{cpg_path}")"""
        try:
            for i in range(0, retry):
                response, _ = self.query(joern_query, 1200)
                if is_imported(response):
                    self._logger.info("CPG is imported successfully")
                    return
                self._logger.info(f"Failed to import CPG (retry: {i + 1}/{retry})")
        except Exception as e:
            self._logger.warning(
                f"""Failed to run joern query
Query: {joern_query}
Exception: {e}"""
            )
        raise RuntimeError("Failed to import cpg")

    def _run(self) -> bool:
        cmd = [
            str(self.joern),
            "--server",
            "--server-port",
            f"{self.__port}",
            "--nocolors",
        ]
        env = self.env.copy()
        env["JAVA_OPTS"] = (
            f"-Xmx{self.__memory}G -XX:ParallelGCThreads=8 -XX:ConcGCThreads=4 -Djava.util.concurrent.ForkJoinPool.common.parallelism=20"
        )
        logger.debug(f"Command for Joern: {" ".join(cmd)}")
        self.__server = subprocess.Popen(
            cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        retry = 60
        while retry > 0:
            try:
                res = self.query("", restart_on_failure=False)[0]
                if (
                    isinstance(res, dict)
                    and "success" in res
                    and res["success"] is True
                ):
                    return True
            except Exception:
                pass
            retry -= 1
            time.sleep(1)
        self.stop()
        return False


class Joern(metaclass=Singleton):
    def __init__(self):
        self._logger = logging.getLogger("joern")
        self._path: Optional[Path] = None
        self._output = tempfile.NamedTemporaryFile(dir=Setting().tmp_dir)
        self._server: Optional[JoernServer] = None

    def close_server(self):
        if self._server is None:
            return

        self._server.stop()
        self._server = None
        self._logger.info("Server stopped")

    def run_server(self, cpg: CPG, script_path: str, semantic: str) -> False:
        if self._path is None:
            self._logger.warning("Set path before run server")
            return False

        # TODO: Simplify basic script for joern
        env = os.environ.copy()
        env["OUT_PATH"] = self._output.name
        env["SEMANTIC_DIR"] = semantic

        scripts = []
        with open(script_path) as f:
            scripts.append(f.read())
            scripts.append("update_semantics")
        self._server = JoernServer(
            self._path,
            env,
            scripts,
        )
        if not self._server.start():
            return False
        self._server.set_cpg(cpg)
        self._logger.info("Server started")
        return True

    def run_query(self, script: str, timeout: int = 120, safe: bool = True) -> Any:
        output_file = tempfile.NamedTemporaryFile(dir=Setting().tmp_dir)
        modified_script: str = f"""
def execute_once = {{
{script}
}}
save_as_json(execute_once, "{output_file.name}")"""
        if safe is True:
            self._server.safe_query(modified_script, timeout)
        else:
            self._server.query_once(modified_script, timeout)
        output_file.seek(0)
        try:
            return json.load(output_file)
        except Exception:
            return None

    # TODO: Do not use this
    def get_sink_name(self, v_type: str) -> str:
        match v_type:
            case "OS Command Injection":
                return "command_injection"
            case "Server Side Request Forgery":
                return "ssrf"
            case "Deserialization":
                return "deserialization"
            case "SQL Injection":
                return "sql_injection"
            case "Remote JNDI Lookup":
                return "naming_context_look_up"
            case "LDAP Injection":
                return "ldap_injection"
            case "XPath Injection":
                return "xpath_injection"
            case "Load Arbitrary Library":
                return "reflective_call"
            case "Regular Expression Injection":
                return "regex_injection"
            case "Script Engine Injection":
                return "script_injection"
            case "File Path Traversal":
                return "arbitrary_file_read_write"
            case "Express Language Injection":
                return "el_injection"
            case _:
                raise RuntimeError(f"Invalid Argument (v_type: {v_type})")

    def set_path(self, path: Path) -> None:
        self._path = path
        self._logger.info(f"path is set to {path}")
