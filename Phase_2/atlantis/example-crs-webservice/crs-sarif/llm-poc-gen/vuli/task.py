import asyncio
import datetime
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

import aiofiles
from langgraph.graph.state import CompiledGraph

from vuli import path_manager
from vuli.agents.exploit import Exploit
from vuli.agents.generator import GeneratorAgent
from vuli.blackboard import Blackboard
from vuli.blobgen import PoVGenerator, SeedGenerator, create_blobgen_factory
from vuli.calltree import UpdateCallTree
from vuli.codereader import create_code_table
from vuli.common.decorators import SEVERITY, async_lock, async_safe, step
from vuli.common.setting import Setting
from vuli.common.singleton import Singleton
from vuli.cp import CP
from vuli.dev import Dev
from vuli.model_manager import ModelManager
from vuli.sink import SinkManager, SinkProperty, SinkStatus
from vuli.struct import CodePoint, Sanitizer, VulInfo


class TaskHandler(ABC):
    @abstractmethod
    async def run(self) -> None:
        pass


class TaskManager(metaclass=Singleton):
    def __init__(self):
        self._logger = logging.getLogger("SyncManager")
        self._handlers = []
        self._stop = False

    def add_handlers(self, *args):
        sync_handlers: list[TaskHandler] = [
            arg for arg in args if isinstance(arg, TaskHandler)
        ]
        if len(sync_handlers) > 0:
            self._handlers.extend(sync_handlers)

    def clear(self) -> None:
        self._handlers = []
        self._stop = False

    async def run(self) -> None:
        self._stop = False
        tasks = [asyncio.create_task(self._run(handler)) for handler in self._handlers]
        await asyncio.gather(*tasks)

    @async_safe(None, SEVERITY.ERROR, "TaskManager")
    async def _run(self, handler) -> None:
        self._logger.info(f"Run Task [task={handler.__class__.__name__}]")
        await handler.run()


class ServiceHandler(TaskHandler):
    def __init__(self, interval: int = 1):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._interval = interval

    async def run(self) -> None:
        while TaskManager()._stop is False:
            await self._service()
            await asyncio.sleep(self._interval)

    @async_safe(None, SEVERITY.ERROR, "ServiceHandler")
    async def _service(self) -> None:
        await self._run()

    @abstractmethod
    async def _run(self) -> None:
        pass


class SyncCallGraph(ServiceHandler):
    def __init__(self, interval: int = 180):
        super().__init__(interval)
        self._logger = logging.getLogger("SyncCallGraph")
        self._last_update = {}

    @step(None, SEVERITY.ERROR, "SyncCallGraph")
    async def _run(self) -> None:
        result: list[tuple[Path, bool]] = [
            (x, await self._update(x)) for x in CP().cg_paths
        ]
        result: list[Path] = [x[0] for x in result if x[1] is True]
        if len(result) > 0:
            await Blackboard().update_cg(set(result))

    @async_safe(False, SEVERITY.WARNING, "SyncCallGraph")
    async def _update(self, path: Path) -> bool:
        if not path.exists():
            return False
        mtime = datetime.datetime.fromtimestamp(path.stat().st_mtime)
        if str(path) in self._last_update and self._last_update[str(path)] >= mtime:
            return False
        self._last_update[str(path)] = mtime
        self._logger.info(f"Start CallGraph Update [from={str(path)}]")
        await UpdateCallTree().update(path)
        return True


class PathBasedGeneration(ABC):

    @abstractmethod
    async def run(self, path: VulInfo) -> path_manager.Status:
        pass

    async def _to_task(self, harness_id: str, task: VulInfo) -> dict:
        return {
            "candidate": task,
            "code_table": await create_code_table(task.v_paths),
            "harness_id": harness_id,
            "saved_cost": 0.0,
        }


class CoverageBasedGeneration(PathBasedGeneration):

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._counter: int = 0
        self._lock = asyncio.Lock()

    @async_lock("_lock")
    async def _assign_id(self) -> int:
        self._counter += 1
        return self._counter

    @async_safe(
        path_manager.Status.MAY_UNREACHABLE, SEVERITY.WARNING, "CoverageBasedGeneration"
    )
    async def run(self, path: VulInfo) -> path_manager.Status:
        task: dict = await self._to_task(path.harness_id, path)
        if Setting().report_dir is not None:
            task["id"] = await self._assign_id()

        self._logger.info(
            f"Start Generation Reachable Blob [harness={path.harness_id}, sink={path.v_point}]"
        )
        task: dict = await self._reach(task)
        is_reached: bool = "error" not in task and task["reached"] is True
        self._logger.info(
            f"Finish Generation Reachable Blob [reached={is_reached}, harness={path.harness_id}, sink={path.v_point}]"
        )
        if not is_reached:
            await self._summary(task, "unreached")
            return path_manager.Status.MAY_UNREACHABLE

        self._logger.info(
            f"Start Generation PoV [harness={path.harness_id}, sink={path.v_point}]"
        )
        task: dict = await self._exploit(task)
        is_pov: bool = "error" not in task and task["crash"] is True
        self._logger.info(
            f"Finish Generation PoV [pov={is_pov}, harness={path.harness_id}, sink={path.v_point}]"
        )
        if not is_pov:
            await self._summary(task, "reached")
            return path_manager.Status.REACHABLE
        await self._summary(task, "exploited")
        return path_manager.Status.EXPLOITABLE

    async def _reach(self, task: dict) -> dict:
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
        result_state: dict = await graph.ainvoke(input_state, {"recursion_limit": 100})
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

    async def _exploit(self, task: dict) -> dict:
        harness_type: str = "byte" if not self._is_fdp_harness(task) else "fdp"
        generator: PoVGenerator = create_blobgen_factory(
            harness_type
        ).create_pov_generator()
        graph: CompiledGraph = Exploit(generator).compile()
        candidate: VulInfo = task.get("candidate", None)
        if candidate is None:
            task["error"] = "Invalid State for PoV-Blob Generation"
            return task

        v_types: set[str] = await SinkManager().get_bug_types(candidate.sink_id)
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
            result_state: dict = await graph.ainvoke(input_state)
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

    def _is_fdp_harness(self, task: dict) -> bool:
        try:
            point: CodePoint = task["candidate"].v_paths[0]
            return point.method.endswith(
                "com.code_intelligence.jazzer.api.FuzzedDataProvider)"
            )
        except Exception:
            return False

    @async_safe(None, SEVERITY.NORMAL, "CoverageBasedGeneration")
    async def _summary(self, task: dict, result: str) -> None:
        if "id" not in task:
            return
        report_path: Path = Setting().report_dir / str(task["id"])
        vulinfo: VulInfo = task["candidate"]
        async with aiofiles.open(report_path, mode="w", encoding="utf-8") as f:
            await f.write(
                f"""[sink]
{vulinfo.v_paths[-1].method} at {vulinfo.v_paths[-1].path}:{vulinfo.v_paths[-1].line}

[harness]
{vulinfo.harness_id},

[path]
{"\n".join([f"{x.method} at {x.path}:{x.line} {"(executed)" if idx <= task["prev"].eval.last_visit else ""}" for idx, x in enumerate(vulinfo.v_paths)])}

[result]
{result}

[blob]
{task["prev"].blob}

[script]
{task["prev"].script}

[prompt]
{"\n".join([x.pretty_repr() for x in task["prev"].prompt])}
"""
            )


class OneTimeGeneration(PathBasedGeneration):

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)

    @step(path_manager.Status.MAY_UNREACHABLE, SEVERITY.WARNING, "OneTimeGeneration")
    async def run(self, path: VulInfo) -> path_manager.Status:
        task: dict = await self._to_task(path.harness_id, path)
        if Setting().report_dir is not None:
            task["id"] = await self._assign_id()

        task: dict = await self._reach(task)
        if "error" in task:
            self._logger.warning(f"Stopped: Error ({task.get("error", "")})")
            return path_manager.Status.MAY_UNREACHABLE

        if task["reached"] is False:
            await self._summary(task, "unreached")
            self._logger.info(
                "Stopped: Failed to generate corpus that reaches to the sinks"
            )
            return path_manager.Status.MAY_UNREACHABLE

        task: dict = await self._exploit(task)

        if "error" in task:
            await self._summary(task, "reached")
            self._logger.warning(f"Stopped: Error ({task.get("error", "")})")
            path_manager.PathManager().update(path, path_manager.Status.REACHABLE)
            return

        is_pov: bool = task.get("crash", False)
        self._logger.info(f"Finish Blob Generation (result: {is_pov})")
        if is_pov:
            await self._summary(task, "exploited")
            return path_manager.Status.EXPLOITABLE
        await self._summary(task, "reached")
        return path_manager.Status.REACHABLE

    async def _reach(self, task: dict) -> dict:
        harness_type: str = "byte"
        generator: SeedGenerator = create_blobgen_factory(
            harness_type, with_sentinel=False, with_feedback=False
        ).create_seed_generator()
        graph = GeneratorAgent(generator).compile_onetime_gen()
        candidate: VulInfo = task.get("candidate", None)
        if candidate is None:
            task["error"] = "Invalid State for Path-Blob Generation"
            return task
        input_state: dict = {
            "candidate": task.get("candidate", None),
            "code_table": task.get("code_table", {}),
            "harness_id": task.get("harness_id", ""),
        }
        result_state: dict = await graph.ainvoke(input_state, {"recursion_limit": 100})
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

    async def _exploit(self, task: dict) -> dict:
        harness_type: str = "byte"
        generator: PoVGenerator = create_blobgen_factory(
            harness_type, with_sentinel=False, with_feedback=False
        ).create_pov_generator()
        graph: CompiledGraph = Exploit(generator).compile()
        candidate: VulInfo = task.get("candidate", None)
        if candidate is None:
            task["error"] = "Invalid State for PoV-Blob Generation"
            return task

        v_types: set[str] = await SinkManager().get_bug_types(candidate.sink_id)
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
            result_state: dict = await graph.ainvoke(input_state)
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

    @step(None, SEVERITY.NORMAL, "OneTimeGeneration")
    async def _summary(self, task: dict, result: str) -> None:
        if "id" not in task:
            return
        report_path: Path = Setting().report_dir / str(task["id"])
        vulinfo: VulInfo = task["candidate"]
        with report_path.open("w", encoding="utf-8") as f:
            f.write(
                f"""[sink]
{vulinfo.v_paths[-1].method} at {vulinfo.v_paths[-1].path}:{vulinfo.v_paths[-1].line}

[harness]
{vulinfo.harness_id},

[path]
{"\n".join([f"{x.method} at {x.path}:{x.line} {"(executed)" if idx <= task["prev"].eval.last_visit else ""}" for idx, x in enumerate(vulinfo.v_paths)])}

[result]
{result}

[blob]
{task["prev"].blob}

[script]
{task["prev"].script}

[prompt]
{"\n".join([x.pretty_repr() for x in task["prev"].prompt])}
"""
            )


class BlobGeneration(TaskHandler):

    def __init__(
        self, generator: PathBasedGeneration, workers: int = 1, interval: int = 5
    ) -> None:
        self._logger = logging.getLogger(self.__class__.__name__)
        self._generator = generator
        self._semaphore = asyncio.Semaphore(workers)
        self._interval = interval
        self._tasks: set = set()
        self._stop: bool = False

    async def run(self) -> None:
        while True:
            if self._stop is True and len(path_manager.PathManager()._queue) == 0:
                if len(self._tasks) > 0:
                    await asyncio.wait(self._tasks)
                return
            await self._safe_run()

    @async_safe(None, SEVERITY.ERROR, "BlobGeneration")
    async def _safe_run(self) -> None:
        await self._semaphore.acquire()
        need_release: bool = True
        try:
            path: Optional[VulInfo] = await path_manager.PathManager().get()
            if path is None:
                await asyncio.sleep(self._interval)
                return

            task: asyncio.Task = asyncio.create_task(self._run_one(path))
            need_release: bool = False
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        finally:
            if need_release is True:
                self._semaphore.release()

    async def _run_one(self, path: VulInfo) -> None:
        await self._safe_run_one(path)

    @async_safe(None, SEVERITY.ERROR, "BlobGeneration")
    async def _safe_run_one(self, path: VulInfo) -> None:
        try:
            await path_manager.PathManager().update(path, path_manager.Status.ANALYZING)

            if Setting().dev and not self._is_cpv(path):
                result = path_manager.Status.MAY_UNREACHABLE
                self._logger.info(
                    f"Skip Blob Generation [reason=Not related PoV(Dev Only), harness={path.harness_id}, sink={path.v_point}]"
                )
            else:
                result: path_manager.Status = await self._generator.run(path)
                self._logger.info(ModelManager().print_total_usage())
                self._logger.info(
                    f"Done Blob Generation [result={result.name}], harness={path.harness_id}, sink={path.v_point}"
                )

            await path_manager.PathManager().update(path, result)

            status: SinkStatus = (
                SinkStatus.REACHABLE
                if result == path_manager.Status.REACHABLE
                else (
                    SinkStatus.EXPLOITABLE
                    if result == path_manager.Status.EXPLOITABLE
                    else SinkStatus.MAY_UNREACHABLE
                )
            )
            harnesses: set[str] = (
                set({path.harness_id})
                if status == SinkStatus.REACHABLE or status == SinkStatus.EXPLOITABLE
                else set()
            )
            await SinkManager().add(
                (path.sink_id, SinkProperty(harnesses=harnesses, status=status))
            )
        finally:
            self._semaphore.release()

    def _is_cpv(self, path: VulInfo) -> bool:
        return Dev().is_target(
            CP().harnesses.get(path.harness_id, "").get("name", ""),
            path.v_point.path,
            path.v_point.line,
        )
