import asyncio
import logging
import os
import shutil
import psutil
from typing import override, Optional
from libDeepGen.engine import DeepGenEngine
from libDeepGen.submit import ZeroMQSubmit
from libDeepGen.tasks import (
    Task,
    OneShotTask,
    DiffAnalysisTask,
    DiffSummaryAnalyzer,
    ScriptLoaderTask,
    deep_evolve_async, 
    ScriptSelector, 
    ScriptChecker,
)
from concurrent.futures import ProcessPoolExecutor
from libAgents.utils import Project, get_model_by_weights
from pathlib import Path
from typing import Dict, Tuple
from .ipc_utils import AsyncReceiver, TaskContext
from .config import TASK_QUEUE_ADDR, ACK_QUEUE_ADDR, general_models, script_fixing_models, evolve_models
from libCRS.util import run_cmd
from .task_models import OneShotTaskParams, DiffAnalysisTaskParams
import glob

logger = logging.getLogger(__name__)

TEMPFS_DIR = os.environ.get("ENSEMBLER_TMPFS", "/tmpfs")
REACHABILITY_SHARE_DIR = os.environ.get("REACHABILITY_SHARE_DIR")
class DummyTask(Task):
    def __init__(self, project_bundle: Project, harness_id: str):
        super().__init__(
            harness_name=harness_id,
            priority=1,
            dev_attempts=1,
            dev_cost=100.0,
            num_repeat=1,
        )
        self.project_bundle = project_bundle
        self.harness_id = harness_id

    def get_label(self):
        return "dummy"

    async def _run_impl(self):
        res = f"""
import random

def gen_one_seed():
    if random.random() < 0.5:
        return b"Ab3@Lx!Q9f*zWeR7^cM1(dT_uY8gJ4Nh#vK0iE6pO%Bs2$aH+Zt5D&CmjXn=]G[Vab3@lx!q9F*ZwEr7^Cm1)DtU_Y8GJ4nH#Vk0Ie6Po%bS2$Ah+zT5d&cMjxN=[g]v"
    else:
        return b"{bytes(self.harness_id, "utf-8")}"
"""
        return res, 0


script_seed_counts = {}
last_seed_counts = {}


class SeedCountingZeroMQSubmit(ZeroMQSubmit):
    def __init__(
        self,
        proc_map: Dict[str, Tuple[str, str]],
        workdir: Path,
        bind_addr: str = "ipc:///tmp/ipc/haha",
        dealer_timeout: int = 60,
        seed_timeout: int = 300,
    ):
        super().__init__(
            proc_map,
            workdir,
            bind_addr=bind_addr,
            dealer_timeout=dealer_timeout,
            seed_timeout=seed_timeout,
        )

    async def request_seed_submit(self, proc_id, script_id, script, seed_ids):
        # Call parent method to handle actual submission
        await super().request_seed_submit(proc_id, script_id, script, seed_ids)
        if seed_ids:
            script_id = script.sha256
            script_seed_counts[script_id] = script_seed_counts.get(script_id, 0) + len(
                seed_ids
            )
            if (
                script_seed_counts[script_id] - last_seed_counts.get(script_id, 0)
                >= 10000
            ):
                logger.info(
                    f"ZeroMQSubmit Script {script_id} generated {script_seed_counts[script_id]} seeds."
                )

class DeepGenTaskContext(TaskContext):
    def __init__(self, engine, project_info: dict, current_harness: dict, disabled_harnesses: dict):
        self.project_info = project_info
        self.current_harness = current_harness
        self.disabled_harnesses = disabled_harnesses


        logger.info(f"current_harness: {current_harness}")
        logger.info(f"disabled_harnesses: {disabled_harnesses}")

        try:
            logger.info("try to get post build project bundle")
            self.project_bundle = self.__get_post_build_project_bundle()
        except Exception as e:
            logger.error(f"Error during project preparation: {e}", exc_info=True)
            logger.info(f"Using original project bundle")
            self.project_bundle = Project(
                oss_fuzz_home=project_info["ossfuzz_home"],
                project_name=self.project_info["project_name"],
                local_repo_path=self.project_info["local_repo_dir"],
            ).prepare_project_bundle(self.project_info["workdir"])

        logger.info(f"Project bundle: {self.project_bundle}")
        logger.info(f"Project bundle project path: {self.project_bundle.project_path}")
        logger.info(f"Project bundle repo    path: {self.project_bundle.repo_path}")

        self.engine = engine
        self.mode = self.project_info["mode"]
        self.weighted_models = general_models
        self.harness_id_to_task_ids = {}


    def __get_post_build_project_bundle(self):
        origial_project_path = f"{self.project_info['ossfuzz_home']}/projects/{self.project_info['project_name']}"

        atlantis_path = Path(self.project_info["ossfuzz_home"]) / "atlantis"

        if not os.path.exists(atlantis_path):
            raise Exception(f"atlantis_path {atlantis_path} does not exist")

        logger.info(f"atlantis_path: {atlantis_path}")
        node_idx = int(os.environ.get("NODE_IDX", 0))
        local_atlantis_path = os.path.join(TEMPFS_DIR, f"atlantis-{node_idx}")
        logger.info(f"local_atlantis_path: {local_atlantis_path}")

        # copy the whole
        if os.path.exists(local_atlantis_path):
            shutil.rmtree(local_atlantis_path)


        logger.info(f"copying {atlantis_path} to {local_atlantis_path}")
        run_cmd(['rsync', '-av', str(atlantis_path)+'/', str(local_atlantis_path)+'/'])

        # andrew: f'{oss_fuzz_path}/atlantis{cp_mount_path} would be $REPO in the config.yaml. And f'{oss_fuzz_path}/atlantis/src would be $PROJECT.

        cp_mount_path = self.project_info["cp_mount_path"]
        if not cp_mount_path:
            raise Exception("cp_mount_path is not set")

        if cp_mount_path.startswith('/'):
            cp_mount_path = cp_mount_path.lstrip('/')

        post_build_repo_path = os.path.join(local_atlantis_path, cp_mount_path)
        post_build_project_path = os.path.join(local_atlantis_path, "src")

        logger.info(f"post_build_repo_path: {post_build_repo_path}")
        logger.info(f"post_build_project_path: {post_build_project_path}")
        logger.info(f"origial_project_path: {origial_project_path}")

        # copy the .aixcc stuff (merge directories, skip existing files)
        logger.info(f"copying non-existing files from {origial_project_path} to {post_build_project_path}")
        # Use cp with -n flag to not overwrite existing files
        run_cmd(['rsync', '-a', '--ignore-existing', str(origial_project_path)+'/.', str(post_build_project_path)+'/'])
        
        self.project_bundle = Project(
            project_name=self.project_info["project_name"],
            project_path=post_build_project_path,
            repo_path=post_build_repo_path,
        ).prepare_project_bundle(self.project_info["workdir"])

        return self.project_bundle

    async def add_task(self, deepgen_task: Task):
        task_id = await self.engine.add_task(deepgen_task)
        return task_id

    def _track_task_id(self, harness_id: str, task_id: str):
        """Track task IDs for each harness ID"""
        if harness_id not in self.harness_id_to_task_ids:
            self.harness_id_to_task_ids[harness_id] = []
        self.harness_id_to_task_ids[harness_id].append(task_id)
        logger.debug(f"Tracked task {task_id} for harness {harness_id}")

    def get_task_ids_for_harness(self, harness_id: str) -> list:
        """Get all task IDs associated with a harness ID"""
        return self.harness_id_to_task_ids.get(harness_id, [])

    async def remove_tasks(self, harness_id: str):
        if harness_id not in self.harness_id_to_task_ids:
            return
        for task_id in self.harness_id_to_task_ids[harness_id]:
            await self.engine.remove_task(task_id)
        del self.harness_id_to_task_ids[harness_id]

    async def add_dummy_task(self, harness_id: str):
        task = DummyTask(self.project_bundle, harness_id)
        task_id = await self.add_task(task)
        self._track_task_id(harness_id, task_id)
        return task_id

    async def add_one_shot_task(
        self,
        harness_id: str,
        priority: int = 1,
        dev_attempts: int = 1,
        dev_cost: float = 100.0,
        num_repeat: int = 1,
        cache_type: Optional[str] = None,
    ):
        task = OneShotTask(
            project_bundle=self.project_bundle,
            harness_id=harness_id,
            model=get_model_by_weights(self.weighted_models),
            priority=priority,
            dev_attempts=dev_attempts,
            dev_cost=dev_cost,
            num_repeat=num_repeat,
            cache_type=cache_type,
            cache_expire_time=300,
        )
        task_id = await self.add_task(task)
        self._track_task_id(harness_id, task_id)
        return task_id

    async def add_diff_analysis_task(
        self,
        harness_id: str,
        priority: int = 1,
        dev_attempts: int = 1,
        dev_cost: float = 100.0,
        num_repeat: int = 1,
        cache_type: Optional[str] = None,
    ):
        if self.mode != "delta":
            logger.info(
                f"Diff analysis task {harness_id} is not supported in mode {self.mode}"
            )
            return
        task = DiffAnalysisTask(
            project_bundle=self.project_bundle,
            harness_id=harness_id,
            model=get_model_by_weights(self.weighted_models),
            priority=priority,
            dev_attempts=dev_attempts,
            dev_cost=dev_cost,
            num_repeat=num_repeat,
            cache_type=cache_type,
            cache_expire_time=300,
        )
        task_id = await self.add_task(task)
        self._track_task_id(harness_id, task_id)
        return task_id

    async def add_diff_sum_analysis_task(
        self,
        harness_id: str,
        priority: int = 1,
        dev_attempts: int = 1,
        dev_cost: float = 100.0,
        num_repeat: int = 1,
        cache_type: Optional[str] = None,
    ):
        if self.mode != "delta":
            logger.info(
                f"Diff analysis task {harness_id} is not supported in mode {self.mode}"
            )
            return
        if not os.path.exists(REACHABILITY_SHARE_DIR):
            return
        if not any(fname.startswith("whole-") and fname.endswith(".json") 
            for fname in os.listdir(REACHABILITY_SHARE_DIR)):
            return
        task = DiffSummaryAnalyzer(
            project_bundle=self.project_bundle,
            harness_id=harness_id,
            model=get_model_by_weights(self.weighted_models),
            priority=priority,
            dev_attempts=dev_attempts,
            dev_cost=dev_cost,
            num_repeat=num_repeat,
            cache_type=cache_type,
        )
        task_id = await self.add_task(task)
        self._track_task_id(harness_id, task_id)
        return task_id

    async def add_tasks_for_harness(self, harness_id: str):
        await self.add_one_shot_task(
            harness_id=harness_id,
            num_repeat=2,
            cache_type="disk",
            priority=1,
            dev_attempts=2,
            dev_cost=100.0,
        )
        await asyncio.sleep(1)

        await self.add_diff_analysis_task(
            harness_id=harness_id,
            num_repeat=2,
            cache_type="disk",
            priority=1,
            dev_attempts=2,
            dev_cost=100.0,
        )
        await asyncio.sleep(1)

        await self.add_diff_sum_analysis_task(
            harness_id=harness_id,
            num_repeat=2,
            cache_type="disk",
            priority=1,
            dev_attempts=2,
            dev_cost=100.0,
        )
        await asyncio.sleep(1)


async def dispatching_loop(context: DeepGenTaskContext):
    cnt = 0
    while True:
        try:
            cnt += 1
            logger.info(f"[DISPATCHING] heartbeat {cnt}")
            logger.info(f"[DISPATCHING] current_harness: {context.current_harness}")
            logger.info(f"[DISPATCHING] disabled_harnesses: {context.disabled_harnesses}")

            if "disable_harness_id" in context.current_harness:
                logger.warning(f"[DISPATCHING] Removing tasks for disabled harness {context.current_harness['disable_harness_id']}")
                await context.remove_tasks(context.current_harness["disable_harness_id"])
                context.current_harness.pop("disable_harness_id", None)
                await asyncio.sleep(60)

            if "harness_id" not in context.current_harness:
                logger.warning(f"[DISPATCHING] No harness_id in current_harness, skipping")
                await asyncio.sleep(60)
                continue

            harness_id = context.current_harness["harness_id"]

            if harness_id in context.disabled_harnesses:
                logger.warning(f"[DISPATCHING] Harness {harness_id} is disabled, skipping")
                await asyncio.sleep(60)
                continue
        

            logger.info("************************************************")
            logger.info(f"*** [DISPATCHING] current_harness: {context.current_harness}")
            logger.info(f"*** [DISPATCHING] disabled_harnesses: {context.disabled_harnesses}")
            logger.info("************************************************")

            await context.add_tasks_for_harness(harness_id)
            logger.info(f"[DISPATCHING] Successfully added tasks for harness {harness_id}")

            await asyncio.sleep(60)
        except Exception as e:
            logger.error(f"[DISPATCHING] Loop error: {e}", exc_info=True)
            await asyncio.sleep(10)

async def keep_evolving(engine, context: DeepGenTaskContext):
    bundle_name = context.project_bundle.name
    bundle_project_path = context.project_bundle.project_path
    bundle_repo_path = context.project_bundle.repo_path

    selector = ScriptSelector("/deepgen_service/workdir-libDeepGen/summary.json")
    cnt = 0
    while True:
        try:
            cnt += 1
            logger.info(f"[DeepEvolve] heartbeat {cnt}")
            logger.warning(f"[DeepEvolve] Picking a script to evolve")
            label, harness_name, script_content = selector.pick_next_script()

            if label is None:
                logger.warning("[DeepEvolve] Failed to pick a script to evolve (No scripts yet?) we will wait for 100 seconds")
                await asyncio.sleep(100)
                continue

            if "harness_id" in context.current_harness and context.current_harness["harness_id"] != harness_name:
                logger.warning(f"[DeepEvolve] Harness {harness_name} is not the current harness, repicking a script")
                await asyncio.sleep(100)
                continue

            logger.warning("================================================")
            logger.warning(f"===>> [DeepEvolve] Evolving script {label} with harness {harness_name}")
            logger.warning("================================================")


            model = get_model_by_weights(evolve_models)
            logger.warning(f"[DeepEvolve] Evolve agent started with model {model}")

            script_content = await deep_evolve_async(
                bundle_name,
                bundle_project_path,
                bundle_repo_path,
                harness_name,
                script_content,
                model
            )

            if script_content is None:
                logger.warning("[DeepEvolve] Evolve agent failed to generate a new script")
                continue

            fix_models = script_fixing_models
            
            checker = ScriptChecker(get_model_by_weights(fix_models), script_content, 10)
            script_content = await checker.check()

            if script_content is None:
                logger.warning("[DeepEvolve] Script checker failed to fix the script")
                continue

            # new_label = label if label.endswith("-evolve") else label+"-evolve"

            task = ScriptLoaderTask(
                script_content=script_content,
                harness_name=harness_name,
                priority=10,
                dev_attempts=2,
                dev_cost=0.0,  # No generation cost for loading scripts
                num_repeat=1
            )
            await engine.add_task(task)
            logger.warning(f"[DeepEvolve] Evolved {cnt} scripts")
            await asyncio.sleep(100)
        except Exception as e:
            logger.error(f"[DeepEvolve] Loop error: {e}", exc_info=True)
            await asyncio.sleep(20)


async def long_running_engine_worker(project_info: dict, current_harness: dict, disabled_harnesses: dict):
    psutil.Process().cpu_affinity([project_info["cores"][0]])
    try:
        async with DeepGenEngine(
            core_ids=project_info["cores"][1:],
            submit_class=SeedCountingZeroMQSubmit,
            seed_max_size=262144,
            seed_pool_size=10000,
            n_exec=1000,
            task_para=3,
            shm_label=project_info["shm_label"],
        ) as engine:
            context = DeepGenTaskContext(engine, project_info, current_harness, disabled_harnesses)

            engine_task = asyncio.create_task(engine.run())
            dispatch_task = asyncio.create_task(dispatching_loop(context))
            evolve_task = asyncio.create_task(keep_evolving(engine, context))
            await asyncio.gather(engine_task, dispatch_task, evolve_task)


        # Print summary of seed counts
        logger.info("Engine execution completed.")
        logger.info("Seed count summary:")
        for script_id, count in script_seed_counts.items():
            logger.info(f"Script {script_id}: {count} seeds")

    except Exception as e:
        logger.error(f"Error during execution: {e}", exc_info=True)


def start_engine_worker(project_info: dict, current_harness: dict, disabled_harnesses: dict):
    asyncio.run(long_running_engine_worker(project_info, current_harness, disabled_harnesses))