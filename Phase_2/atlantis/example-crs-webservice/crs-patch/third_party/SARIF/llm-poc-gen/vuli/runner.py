import os
import tempfile
import asyncio
import logging
import pickle
import time
import traceback
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import requests
from langgraph.graph.state import CompiledGraph
from vuli import path_manager
from vuli.agents.exploit import Exploit
from vuli.agents.generator import GeneratorAgent
from vuli.agents.reflection import ReflectionSolver
from vuli.blobgen import PoVGenerator, SeedGenerator, create_blobgen_factory
from vuli.calltree import CallTree
from vuli.codereader import create_code_table
from vuli.common.setting import Setting, Storage, StorageDataStatus
from vuli.cp import CP
from vuli.delta import Delta
from vuli.dev import Dev
from vuli.joern import CPG, Joern
from vuli.model_manager import ModelManager
from vuli.path_manager import PathManager
from vuli.pathfinder import PathFinder
from vuli.sariflog import SarifLog
from vuli.query_loader import QueryLoader
from vuli.scan import Origin, Scanner, SinkManager, SinkProperty, Status
from vuli.struct import CodePoint, Sanitizer, VulInfo


class Runner(ABC):
    def __init__(self, max_workers: int = 1):
        self._logger = logging.getLogger("Runner")
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="BlobGenerator"
        )
        self._running_tasks = set()
        self._semaphore = asyncio.Semaphore(max_workers)
        self._stop_sink_to_path: bool = False
        self._stop_generation_if_no_path: bool = False

    @abstractmethod
    async def _run(self) -> None:
        pass

    async def run(self) -> None:
        start_time = time.time()
        try:
            QueryLoader("c")

            harness_names: list[str] = CP().get_harness_names()
            if len(harness_names) == 0:
                self._logger.info("Harness not found: Terminated")
                return

            self._logger.info(f"Harnesses: {",".join(harness_names)}")

            self._initialize_joern()
            self._scan()

            self._logger.info("Building Initial CallGraph")
            CallTree().open(Setting().calltree_db_path)
            CallTree().build(CP().get_harness_names())

            if True:
                pass
            else:
                self._logger.info("Solving Reflections")
                [
                    self._solve_reflections(CP().get_harness_path(x))
                    for x in CP().get_harness_names()
                ]

            self._update_from_delta()
            await self._run()
        finally:
            self._save_output(start_time)
            Joern().close_server()
            CallTree().close()

        self._logger.info(f"LLM Usage:\n{ModelManager().print_total_usage()}")

    def _initialize_joern(self):
        cpg: CPG = CPG(Setting().cpg_path)
        if not cpg.path.exists():
            self._logger.info("Building CPG")
            exclude_dirs: list[Path] = []
            cpg.build(
                Path(Setting().joern_javasrc_path),
                Path(CP().source_dir),
                exclude_dirs,
                CP().get_dependent_jars(),
            )

        self._logger.info("Run Joern Server")
        Joern().set_path(Setting().joern_cli_path)
        if not Joern().run_server(cpg, Setting().query_path, Setting().semantic_dir):
            raise RuntimeError("Failed to run Joern Server")

    def _scan(self):
        if Setting().sarif_path:
            self.scan_sarif(Setting().sarif_path)
        else:
            self.scan_default()

    def scan_default(self):
        Scanner().scan(CP().sanitizers)

    def scan_sarif(self, sarif_path: Path):
        sarif_log = SarifLog(sarif_path)
        sarif_log.extract()

    def _solve_reflections(self, harness_path: str) -> None:
        exclude: list[int] = []
        solver = ReflectionSolver(Joern()).compile()
        while True:
            try:
                result = solver.invoke(
                    {"harness_path": harness_path, "exclude": exclude}
                )
            except Exception:
                self._logger.warning("Reflection solver failed but keep going")
                break
            edges: list[tuple[list[int], list[int]]] = result.get("result", [])
            updated: bool = True in [
                CallTree().insert(src, set(dsts))
                for srcs, dsts in edges
                for src in srcs
            ]
            if not updated:
                break
            self._logger.info("Call DB is updated")
            exclude: list[int] = [
                x[-1] for x in result.get("verified_paths", []) if len(x) > 0
            ]

    def _update_from_delta(self) -> None:
        diff_path: Optional[Path] = CP()._diff_path
        if diff_path is None:
            self._logger.info("Diff File Not Found")
            return

        sinks: list[dict] = Delta().get_sinks(diff_path)
        self._logger.info(f"Found {len(sinks)} Sinks From Diff")

        query: list[str] = [
            f'("{sink["file_path"]}", {sink["line"]}, "{sink["v_type"]}")'
            for sink in sinks
        ]
        query: str = f"""
List({",".join(query)})
    .map(x => (cpg.call.where(_.method.filename(".*" + x._1)).where(_.lineNumber(x._2)).headOption, x._3))
    .collect{{case (Some(a), b) => Map("id" -> a.id, "v_type" -> b)}}"""
        result: list[dict] = Joern().run_query(query)
        self._logger.info(f"Found {len(result)} Nodes in Joern")
        self._logger.debug(result)

        [
            SinkManager().add(
                (
                    x["id"],
                    SinkProperty(
                        bug_types=set({x["v_type"]}), origins=set({Origin.FROM_DELTA})
                    ),
                )
            )
            for x in result
        ]

    async def sink_to_path(self) -> None:
        """
        (1) This will run forever unless a specific flag set
        (2) This will start when there is any update from calltree
        (3) This will find paths from sinks from SinkManager where it's status is unknown
        """
        while not self._stop_sink_to_path:
            if CallTree()._updated:
                CallTree()._updated = False
                self._sink_to_path()
            await asyncio.sleep(1)

    def _sink_to_path(self) -> None:
        """
        UNKNOWN sinks from SinkManager will be converted to paths if possible
        """
        sinks: set[int] = {
            key
            for key, value in SinkManager().get().items()
            if (
                value.status == Status.UNKNOWN or value.status == Status.MAY_UNREACHABLE
            )
        }
        self._logger.info(f"Target sinks: {len(sinks)}")
        self._logger.debug(f"Sinks: {",".join([str(sink) for sink in sinks])}")

        runner = PathFinder()
        found_sinks: set[int] = set()
        for harness_name in CP().get_harness_names():
            paths: list[VulInfo] = runner.find(harness_name, sinks)
            for path in paths:
                self._logger.info(
                    f"New Path Found [harness={harness_name}, sinks={",".join([str(path.sink_id) for path in paths])}]"
                )
                SinkManager().update_status(path.sink_id, Status.MAY_REACHABLE)
                PathManager().add(path)
                found_sinks.add(path.sink_id)

        not_found_sinks: set[int] = sinks - found_sinks
        self._logger.info(f"Not Found Sinks: {len(not_found_sinks)}")
        self._logger.debug(
            f"Sinks: {",".join([str(sink) for sink in not_found_sinks])}"
        )
        [
            SinkManager().update_status(sink, Status.MAY_UNREACHABLE)
            for sink in not_found_sinks
        ]

    async def _generate_blob(self):
        while True:
            await self._semaphore.acquire()
            need_to_release_semaphore: bool = True
            try:
                path: Optional[VulInfo] = PathManager().get()
                if path is None:
                    if self._stop_generation_if_no_path:
                        if len(self._running_tasks) > 0:
                            await asyncio.wait(self._running_tasks)
                        break
                    await asyncio.sleep(5)
                    continue

                task = asyncio.create_task(self._generate_blob_in_parallel(path))
                self._running_tasks.add(task)
                task.add_done_callback(self._running_tasks.discard)
                need_to_release_semaphore = False
            except Exception as e:
                self._logger.warning(f"Skip exception while generating blob: {e}")
                traceback.print_exc()
            finally:
                if need_to_release_semaphore:
                    self._semaphore.release()

    async def _generate_blob_in_parallel(self, path: VulInfo) -> None:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(self._executor, self._path_to_blob, path)
        finally:
            self._semaphore.release()

    def _path_to_blob(self, path: VulInfo) -> None:
        PathManager().update(path, path_manager.Status.ANALYZING)
        self._logger.info(
            f"Start Blob Generation [harness_id:{path.harness_id}, target:{path.v_point}]"
        )
        self._logger.debug(path)
        task: dict = self._to_task(path.harness_id, path)
        if Setting().dev and not self._is_cpv(path.harness_id, task):
            self._logger.info(
                f"Stopped: Not Related to CPV[harness={path.harness_id}, sink={path.v_point}]"
            )
            PathManager().update(path, path_manager.Status.MAY_UNREACHABLE)
            return

        task: dict = self._generate_seed(task)
        if "error" in task:
            self._logger.warning(f"Stopped: Error ({task.get("error", "")})")
            PathManager().update(path, path_manager.Status.MAY_UNREACHABLE)
            return

        if task["reached"] is False:
            self._logger.info(
                "Stopped: Failed to generate corpus that reaches to the sinks"
            )
            PathManager().update(path, path_manager.Status.MAY_UNREACHABLE)
            return

        task: dict = self._generate_pov(task)
        prev = task.get("prev")
        if prev is not None:
            blob = prev.blob
            shared_dir = Setting().shared_dir
            os.makedirs(shared_dir, exist_ok=True)

            with tempfile.NamedTemporaryFile(
                dir=shared_dir, suffix=".bin", delete=False
            ) as tmp_file:
                tmp_file.write(blob)

        if "error" in task:
            self._logger.warning(f"Stopped: Error ({task.get("error", "")})")
            PathManager().update(path, path_manager.Status.REACHABLE)
            return

        is_pov: bool = task.get("crash", False)
        self._logger.info(f"Finish Blob Generation (result: {is_pov})")
        if is_pov:
            PathManager().update(path, path_manager.Status.EXPLOITABLE)
        else:
            PathManager().update(path, path_manager.Status.REACHABLE)

    def _to_task(self, harness_id: str, task: VulInfo) -> dict:
        return {
            "candidate": task,
            "code_table": create_code_table(task.v_paths),
            "harness_id": harness_id,
            "saved_cost": 0.0,
        }

    def _is_cpv(self, harness_id: str, task: dict) -> bool:
        candidate: VulInfo = task.get("candidate", None)
        if candidate is None:
            task["error"] = "Invalid State for CPV Checking"
            return False

        return Dev().is_target(
            CP().harnesses.get(harness_id, "").get("name", ""),
            candidate.v_point.path,
            candidate.v_point.line,
        )

    def _generate_seed(self, task: dict) -> dict:
        harness_type: str = "byte" if not self._is_fdp_harness(task) else "fdp"
        generator: SeedGenerator = create_blobgen_factory(
            harness_type
        ).create_seed_generator()
        graph = GeneratorAgent(generator).compile()
        candidate: VulInfo = task.get("candidate", None)
        if candidate is None:
            task["error"] = "Invalid State for Path-Blob Generation"
            return task
        input_state: dict = {
            "candidate": task.get("candidate", None),
            "code_table": task.get("code_table", {}),
            "harness_id": task.get("harness_id", ""),
        }
        result_state, err = self._run_graph(
            graph, input_state, {"recursion_limit": 100}
        )
        if err:
            task["error"] = err
            return task
        necessary_keys: set[str] = {"code_table", "point", "prev", "reached"}
        missing_keys: set[str] = necessary_keys - set(result_state.keys())
        if len(missing_keys) > 0:
            task["error"] = (
                f"No Output From Path-Blob Generation ({", ".join(missing_keys)})"
            )
            return task
        task["code_table"] = result_state["code_table"]
        task["point"] = result_state["point"]
        task["reached"] = result_state["reached"]
        task["prev"] = result_state["prev"]
        return task

    def _generate_pov(self, task: dict) -> dict:
        harness_type: str = "byte" if not self._is_fdp_harness(task) else "fdp"
        if True:
            generator: PoVGenerator = create_blobgen_factory(
                harness_type
            ).create_pov_generator(with_sentinel=False)
        else:
            generator: PoVGenerator = create_blobgen_factory(
                harness_type
            ).create_pov_generator()
        graph: CompiledGraph = Exploit(generator).compile()
        candidate: VulInfo = task.get("candidate", None)
        if candidate is None:
            task["error"] = "Invalid State for PoV-Blob Generation"
            return task

        v_types: set[str] = SinkManager().get_bug_types(candidate.sink_id)
        for v_type in v_types:
            sanitizer: Optional[Sanitizer] = CP().get_sanitizer(v_type)
            if sanitizer is None:
                sanitizer = Sanitizer(name=v_type, sentinel=[])
            input_state: dict = {
                "code_table": task["code_table"],
                "harness_id": task["harness_id"],
                "path": candidate.v_paths,
                "prev": task["prev"],
                "point": task["point"],
                "sanitizer": sanitizer,
            }
            result_state, err = self._run_graph(graph, input_state)
            if err:
                task["error"] = err
                continue
            necessary_keys: set[str] = {"crash", "prev"}
            missing_keys: set[str] = necessary_keys - set(result_state.keys())
            if len(missing_keys) > 0:
                task["error"] = (
                    f"No Output From PoV-Blob Generation ({", ".join(missing_keys)})"
                )
                continue
            task["crash"] = result_state["crash"]
            task["prev"] = result_state["prev"]
            task["v_type"] = v_type
            return task
        task["crash"] = False
        return task

    def _run_graph(
        self, graph: CompiledGraph, input: dict, config: dict = None
    ) -> tuple[dict, Optional[str]]:
        error_msg: str = None
        last_state: dict = input
        try:
            for event in graph.stream(input, config, stream_mode="values"):
                last_state = event
        except Exception as e:
            traceback.print_exc()
            error_msg = str(e)
        return (last_state, error_msg)

    def _is_fdp_harness(self, task: dict) -> bool:
        try:
            point: CodePoint = task["candidate"].v_paths[0]
            return point.method.endswith(
                "com.code_intelligence.jazzer.api.FuzzedDataProvider)"
            )
        except Exception:
            return False

    def _save_output(self, start_time: time.time) -> None:
        running_time: time.time = time.time() - start_time
        Storage().set_time(running_time)

        sinks: dict[int, SinkProperty] = SinkManager().get()
        if len(sinks.keys()) > 0:
            joern_query: str = f"""
    cpg.ids({",".join([str(x) for x in sinks.keys()])})
        .collect{{case x: CfgNode => x}}
        .map(x => x.id -> Map(
            "file_path" -> x.method.filename,
            "line" -> x.lineNumber.getOrElse(-1),
            "column" -> x.columnNumber.getOrElse(-1)
        )).toMap"""
            joern_result: dict = Joern().run_query(joern_query)
            for id, property in sinks.items():
                location: dict = joern_result.get(str(id), {})
                file_path: str = location.get("file_path", "")
                try:
                    line: int = int(location.get("line", 0))
                except ValueError:
                    line = -1
                try:
                    column: int = int(location.get("column", 0))
                except ValueError:
                    column = -1
                Storage().add_sink(file_path, line, column, list(property.bug_types))

        for key, status in PathManager()._table.items():
            vul_info: VulInfo = pickle.loads(key)
            storage_status: StorageDataStatus = StorageDataStatus.NOT_REACHED
            if status == path_manager.Status.REACHABLE:
                storage_status = StorageDataStatus.REACHED
            elif status == path_manager.Status.EXPLOITABLE:
                storage_status = StorageDataStatus.EXPLOITED
            Storage().add_path(
                vul_info.harness_id,
                vul_info.v_paths,
                list(SinkManager().get_bug_types(vul_info.sink_id)),
                storage_status,
            )
        Storage().save()


class StandAlone(Runner):
    def __init__(self, workers: int):
        super().__init__(workers)
        self._logger = logging.getLogger("StandAlone")
        self._quit: bool = False

    async def _run(self) -> None:
        tasks = [self._find_paths(), self._generate_blob()]
        await asyncio.gather(*tasks)

    async def _find_paths(self) -> None:
        try:
            self._sink_to_path()
        except Exception as e:
            self._logger.warning(f"Exception: {e.__class__.__name__}: {e}")
        self._stop_generation_if_no_path = True


class CRS(Runner):
    def __init__(self, period: int = 5, port: int = 10100, workers: int = 1):
        super().__init__(workers)
        self._logger = logging.getLogger("CRS")
        self._period: int = period
        self._port: int = port
        self._stop: bool = False

    async def _run(self) -> None:
        tasks = [self._handle_crs_request(), self.sink_to_path(), self._generate_blob()]
        await asyncio.gather(*tasks)

    async def _handle_crs_request(self) -> None:
        while not self._stop:
            self._check()
            await asyncio.sleep(self._period)
        self._stop_sink_to_path = True
        self._stop_generation_if_no_path = True

    def _check(self):
        url: str = f"http://127.0.0.1:{self._port}"
        try:
            response = requests.get(url)
        except Exception:
            self._logger.warning(f"[SKIP] Failed to get request from CRS (URL: {url})")
            return

        if response.status_code != 200:
            self._logger.warning(f"[SKIP] Failed to get request from CRS (URL: {url})")
            return

        response_json: dict = response.json()
        if "command" not in response_json:
            self._logger.warning(
                f"[SKIP] Invalid format ['command' not found] (JSON: {response_json})"
            )
            return

        command: str = response_json["command"]
        if command == "sarif":
            self._make_sarif_task(response_json)
        elif command == "callgraph":
            self._update_callgraph(response_json)
        elif command == "quit":
            self._stop = True
        else:
            self._logger.warning(
                f"[SKIP] Invalid format [unknown `{command}` is found for `command`] (JSON: {response_json})"
            )

    def _make_sarif_task(self, response_json: dict) -> None:
        # (TODO) We don't know the format that CRS will request yet.
        necessary_keys: set[str] = {"file_path", "line_number"}
        missing_keys: set[str] = {x for x in necessary_keys if x not in response_json}
        if len(missing_keys) > 0:
            self._logger.warning(
                f"[SKIP] Invalid format [{",".join([f"'{x}'" for x in missing_keys])} not found for sarif command] (JSON: {response_json})"
            )
            return

        try:
            file_path: Path = Path(response_json["file_path"])
            line_number: int = int(response_json["line_number"])
        except Exception as e:
            self._logger.warning(
                f"[SKIP] Invalid format [{e.__class__.__name__}: {e}] (JSON: {response_json})"
            )
            return

        self._logger.info(
            f"SARIF Accepted[file_path={file_path},line_number={line_number}]"
        )
        self._sarif_to_sink(file_path, line_number)

    def _update_callgraph(self, response_json: dict) -> None:
        call_path: list[dict] = response_json.get("callpath", [])
        joern_query: str = "val path = List("
        for x in call_path:
            class_name: str = x.get("classname", "").replace("$", "\\\\$")
            method: str = x.get("method", "")
            line: int = x.get("line", -1)
            joern_query += f'("{class_name}", "{method}", {line}),'
        if joern_query[-1] == ",":
            joern_query = joern_query[:-1]
        joern_query += ")"
        joern_query += """
path.map(x =>
    cpg.method.fullName(s"${x._1}.${x._2}.*")
        .where(_.lineNumberLte(x._3))
        .where(_.lineNumberEndGte(x._3))
        .where(_.isExternal(false)).headOption)
    .collect{case Some(x) => x.id}"""
        joern_result: list[int] = Joern().run_query(joern_query)
        for i in range(0, len(joern_result) - 1):
            CallTree().insert(joern_result[i], {joern_result[i + 1]})

    def _sarif_to_sink(self, file_path: Path, line_number: int) -> None:
        joern_query: str = f"""
def firstNode(method: Method): CfgNode = {{
    val node: CfgNode = method.cfgFirst.head
    node.lineNumber match {{
        case Some(x) => node
        case _ => method.call.map(x => (x, x.lineNumber)).collect{{case (a, Some(b)) => (a, b)}}.sortBy(_._2).head._1
    }}
}}
val method = cpg.method.where(_.filename(".*{file_path}")).l
val calls = method.call.where(_.lineNumber({line_number})).l
val args = calls.argument.map(x => (x, x.lineNumber)).collect{{case (a, Some(b)) => a}}.l
Map(
    "calls" -> calls.sortBy(_.columnNumber).id.l,
    "args" -> args.id.l,
    "firsts" -> method.where(_.and(_.lineNumberLte({line_number}), _.lineNumberEndGte({line_number}))).map(firstNode).id.l
)
"""
        joern_result: dict = Joern().run_query(joern_query)
        calls: list[int] = joern_result.get("calls", [])
        args: list[int] = joern_result.get("args", [])
        firsts: list[int] = joern_result.get("firsts", [])
        call_args: set[int] = set(calls + args)
        existing_sinks: set[int] = set(SinkManager().get().keys()) & call_args
        if len(existing_sinks) > 0:
            sinks_to_add: dict = {
                x: SinkProperty(
                    bug_types=set(),
                    origins={Origin.FROM_SARIF},
                    status=Status.UNKNOWN,
                )
                for x in existing_sinks
            }
            SinkManager().add_batch(sinks_to_add)
            self._logger.info(
                f"Existing sink's origin is updated to SARIF[sinks={",".join([str(x) for x in existing_sinks])}]"
            )
            return
        if len(calls) > 0:
            SinkManager().add(
                (
                    calls[0],
                    SinkProperty(
                        bug_types=set(),
                        origins={Origin.FROM_SARIF},
                        status=Status.UNKNOWN,
                    ),
                )
            )
            self._logger.info(f"New call is added as SARIF sink[sink={calls[0]}]")
            return
        if len(args) > 0:
            SinkManager().add(
                (
                    args[0],
                    SinkProperty(
                        bug_types=set(),
                        origins={Origin.FROM_SARIF},
                        status=Status.UNKNOWN,
                    ),
                )
            )
            self._logger.info(f"New arg is added as SARIF sink[sink={args[0]}]")
            return
        if len(firsts) > 0:
            sinks_to_add: dict = {
                x: SinkProperty(
                    bug_types=set(),
                    origins={Origin.FROM_SARIF},
                    status=Status.UNKNOWN,
                )
                for x in firsts
            }
            SinkManager().add_batch(sinks_to_add)
            self._logger.info(
                f"New method entries are added as SARIF sink[sink={",".join([str(x) for x in firsts])}]"
            )
