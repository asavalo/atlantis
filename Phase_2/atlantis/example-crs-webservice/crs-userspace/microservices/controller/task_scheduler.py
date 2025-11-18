from enum import Enum
from typing import Optional
from dataclasses import dataclass
from collections import deque
from threading import Lock
import random
import logging
from scipy.stats import rankdata
import os

from . import config

logger = logging.getLogger(__name__)

class TaskType(Enum):
    LIBAFL = 0
    LIBFUZZER = 1
    DIRECTED_FUZZER = 2
    CUSTOM_FUZZER = 3
    AFL = 4
    HONGGFUZZ = 5
    UBSAN = 6
    MSAN = 7
    SANS = 8

    @classmethod
    def from_mode(cls, mode: str) -> 'TaskType':
        """Convert a mode string to TaskType."""
        mode_map = {
            "libafl": cls.LIBAFL,
            "libfuzzer": cls.LIBFUZZER,
            "afl": cls.AFL,
            "honggfuzz": cls.HONGGFUZZ,
            "ubsan": cls.UBSAN,
            "msan": cls.MSAN,
            "sans": cls.SANS,
        }
        return mode_map.get(mode, cls.LIBFUZZER)  # Default to LIBFUZZER if mode not found

    def to_mode(self) -> str:
        """Convert TaskType to mode string."""
        mode_map = {
            self.LIBAFL: "libafl",
            self.LIBFUZZER: "libfuzzer",
            self.AFL: "afl",
            self.HONGGFUZZ: "honggfuzz",
            self.UBSAN: "ubsan",
            self.MSAN: "msan",
            self.SANS: "sans",
        }
        return mode_map.get(self, "libfuzzer")  # Default to libfuzzer if type not found

    @classmethod
    def general_fuzzing_modes(cls) -> list['TaskType']:
        """Return the list of task types that are considered general fuzzing modes."""
        return [cls.LIBAFL, cls.AFL, cls.LIBFUZZER, cls.UBSAN, cls.MSAN, cls.SANS]

class DirectedTaskState(Enum):
    UNSTARTED = "unstarted"
    RUNNING = "running"

@dataclass(frozen=True)
class Task:
    type_: TaskType # PEP 8
    harness_id: str | None

@dataclass(frozen=True)
class DirectedTask(Task):
    location: str
    fuzzer_session_id: str
    sarif_id: Optional[str] = None

    def __repr__(self):
        sarif_str = f" sarif:{self.sarif_id}" if self.sarif_id else ""
        return f"{self.harness_id:<12} {self.location}{sarif_str} {self.fuzzer_session_id}"

@dataclass
class DirectedTaskMetadata:
    node_idx: int = -1
    cpu_idx: int = -1
    time_elapsed: int = 0
    state: DirectedTaskState = DirectedTaskState.UNSTARTED

    def __repr__(self):
        return f"node:{self.node_idx} cpu:{self.cpu_idx} time:{self.time_elapsed} {str(self.state)}"

class TaskScheduler:
    def __init__(self, num_sessions: int):
        self.lock = Lock()
        self.num_sessions = num_sessions
        self.tasks = dict() # task -> weight
        self.popped_tasks = dict() # task -> num_popped
        self.queue = deque()

    def log_popped_tasks(self):
        with self.lock:
            if len(self.popped_tasks) > 0:
                logger.info("Task Scheduler Run Report:")
                for task, num_popped in self.popped_tasks.items():
                    logger.info(f"{task.type_} {task.harness_id}: {num_popped}")

    def get_starved_tasks(self) -> list[Task]:
        with self.lock:
            return [task for task, num_popped in self.popped_tasks.items() if num_popped == 0]

    def check_prioritization(self) -> int:
        with self.lock:
            if len(self.tasks) != len(self.popped_tasks):
                logger.error("Tasks and popped tasks have different lengths")
            # safety check
            common_tasks = set(self.tasks.keys()) & set(self.popped_tasks.keys())
            weights = [self.tasks[task] for task in common_tasks]
            pops = [self.popped_tasks[task] for task in common_tasks]
            weight_rank = rankdata(weights, method='average')
            popped_rank = rankdata(pops, method='average')

            # returns the rank difference between the weight and the historical pop count 
            return sum(abs(w - p) for w, p in zip(weight_rank, popped_rank))

    def snapshot_weights(self) -> dict[Task, int]:
        with self.lock:
            return self.tasks.copy()

    def weight_sum(self) -> int:
        with self.lock:
            return sum(self.tasks.values())

    def register_new_tasks(self, tasks: list[Task]):
        logger.info(f"Registering {len(tasks)} new tasks")
        with self.lock:
            for task in tasks:
                if task not in self.tasks:
                    self.tasks[task] = 1
                if task not in self.popped_tasks:
                    self.popped_tasks[task] = 0

    def register_new_task(self, task: Task, weight: int=1):
        logger.info(f"Registering new task {task.type_} {task.harness_id}")
        with self.lock:
            if task in self.tasks and self.tasks[task] >= weight:
                logger.info(f"Task {task.type_} {task.harness_id} already registered with larger weight, skipping")
            else:
                self.tasks[task] = weight
            if task not in self.popped_tasks:
                self.popped_tasks[task] = 0

    def remove_task(self, task: Task):
        logger.info(f"Removing task {task.type_} {task.harness_id}")
        with self.lock:
            weight = 1
            if task in self.tasks:
                weight = self.tasks[task]
                self.tasks[task] = 0
                if task in self.queue:
                    self.queue = deque(x for x in self.queue if x != task)
            return weight

    def update_task_weight(self, task: Task, weight: int):
        logger.info(f"Updating task weight for {task.type_} {task.harness_id} to {weight}")
        with self.lock:
            self.tasks[task] = weight
            if task not in self.popped_tasks:
                self.popped_tasks[task] = 0

    def __get_next_task(self) -> Task:
        if len(self.queue) < 1:
            logger.info("Extending task queue with current weights")
            self.__extend_queue()
        task = self.queue.popleft()
        if task in self.popped_tasks:
            self.popped_tasks[task] += 1
        else:
            self.popped_tasks[task] = 1
        return task
    
    def __extend_queue(self):
        task_list = []
        # NOTE debugging override
        hardcoded_harnesses = os.environ.get('OVERRIDE_HARNESSES')
        if hardcoded_harnesses:
            # Parse comma-separated harness IDs
            harness_ids = [h.strip() for h in hardcoded_harnesses.split(',')]
            
            # Filter tasks to only include those with matching harness IDs
            filtered_tasks = []
            for task, _ in self.tasks.items():
                if task.harness_id in harness_ids:
                    filtered_tasks.append(task)
            
            if filtered_tasks:
                task_list = filtered_tasks
        if not task_list:
            # Normal behavior - use all tasks
            for task, weight in self.tasks.items():
                task_list.extend([task] * weight)
            random.shuffle(task_list)
            
        self.queue.extend(task_list)

    def push_tasks_immediately(self, tasks: list[Task]):
        with self.lock:
            self.queue.extendleft(tasks)

    def apply_task_weights_immediately(self):
        with self.lock:
            self.queue.clear()
            self.__extend_queue()

    def get_tasks_for_epoch(self) -> list[Task]:
        # the rule is to always exactly get num_sessions for atlantis fuzzer
        with self.lock:
            task_list = []
            atlantis_fuzzer_count = 0
            while atlantis_fuzzer_count < self.num_sessions:
                task = self.__get_next_task()
                if task.type_ in TaskType.general_fuzzing_modes():
                    atlantis_fuzzer_count += 1
                task_list.append(task)
            return task_list

# NOTE we control this scheduler via cond in caller rather than internal lock
#      this frees us up to call helpers without worrying about re-entrance
class DirectedTaskScheduler(TaskScheduler):
    def __init__(self, num_sessions: int):
        super().__init__(num_sessions)
        self.current_taskset = set()
        self.full_capacity = len(config.CORES_FOR_DIRECTED) * self.num_sessions
        self.task_metadata = {}  # task -> DirectedTaskMetadata

    def __sarif_taskset(self) -> list[DirectedTask]:
        return [task for task in self.current_taskset if task.sarif_id is not None]
    
    def __non_sarif_taskset(self) -> list[DirectedTask]:
        return [task for task in self.current_taskset if task.sarif_id is None]

    def __task_iterable_to_metadata_tuple(self, tasks) -> list[tuple[DirectedTask, DirectedTaskMetadata]]:
        return [(task, self.task_metadata[task]) for task in tasks]
    
    # Put this here because TaskScheduler should not expose it in public interface
    def queue_tasks(self, tasks: list[DirectedTask]):
        self.queue.extend(tasks)
        # Initialize metadata for new tasks
        for task in tasks:
            if task not in self.task_metadata:
                self.task_metadata[task] = DirectedTaskMetadata()

    def queue_tasks_immediately(self, tasks: list[Task]):
        self.queue.extendleft(tasks)
        for task in tasks:
            if task not in self.task_metadata:
                self.task_metadata[task] = DirectedTaskMetadata()

    def remove_directed_task(self, task: DirectedTask):
        if task in self.current_taskset:
            self.current_taskset.remove(task)
        if task in self.queue:
            self.queue.remove(task)
        if task in self.task_metadata:
            del self.task_metadata[task]

    def remove_tasks_by_location(self, location: str) -> list[tuple[DirectedTask, DirectedTaskMetadata]]:
        to_stop_tasks = []
        # for task in current_taskset and queue, if location matches call remove_directed_task
        for task in self.current_taskset:
            if task.location == location:
                self.remove_directed_task(task)
                to_stop_tasks.append((task, self.task_metadata[task]))
        for task in self.queue:
            if task.location == location:
                self.remove_directed_task(task)
                # don't stop because not running... dumb ai
        return to_stop_tasks

    def evict_tasks(self, n: int = 1) -> list[tuple[DirectedTask, DirectedTaskMetadata]]:
        """
        Evicts up to n tasks if all available allocations for directed fuzzing are full.
        
        We would like to evict the longest running non-sarif task.
        If all running tasks are SARIF, then we'll evict the longest SARIF.
        """
        removed_tasks = []
        if len(self.current_taskset) + n <= self.full_capacity:
            return removed_tasks
        # evict just enough to fit n new tasks
        num_tasks_to_evict = n - (self.full_capacity - len(self.current_taskset))
        for _ in range(num_tasks_to_evict):
            if len(self.current_taskset) == 0:
                return removed_tasks
            # filter out tasks that have a sarif_id
            non_sarif_taskset = self.__non_sarif_taskset()
            to_check = non_sarif_taskset if len(non_sarif_taskset) > 0 else self.current_taskset
            # find task in current_taskset with greatest time_elapsed
            longest_running_task = max(to_check, key=lambda x: self.task_metadata[x].time_elapsed)
            removed_tasks.append(longest_running_task)
            self.current_taskset.remove(longest_running_task)
            self.queue.append(longest_running_task)
        # return to caller in order to actually shut down
        return self.__task_iterable_to_metadata_tuple(removed_tasks)
            
    def update_task_state(self, task: DirectedTask, state: DirectedTaskState):
        if task not in self.task_metadata:
            logger.error(f"Could not retrieve the metadata -- {task}")
            return
        metadata = self.task_metadata[task]
        if metadata.state == state:
            logger.warning(f"Task's state is already set to {state} -- {task}")
        metadata.state = state
    
    def update_taskset_time_elapsed(self, time_elapsed: int):
        for task in self.current_taskset:
            metadata = self.task_metadata[task]
            if metadata.state != DirectedTaskState.UNSTARTED:
                metadata.time_elapsed += time_elapsed
            
    def rotate_tasks(self) -> list[tuple[DirectedTask, DirectedTaskMetadata]]:
        non_sarif = self.__non_sarif_taskset()
        removed_tasks = set()
        # NOTE do not evict unless full, can comment for testing
        if len(self.current_taskset) + len(self.queue) <= self.full_capacity:
            return []
        max_removal = len(self.queue)
        for task in non_sarif:
            if len(removed_tasks) >= max_removal:
                return self.__task_iterable_to_metadata_tuple(removed_tasks)
            if (self.task_metadata[task].state == DirectedTaskState.RUNNING
                and self.task_metadata[task].time_elapsed >= config.DIRECTED_TASK_RUN_THRESHOLD):
                logger.info(f"Task has run for long, rotating {task}")
                removed_tasks.add(task)
                self.current_taskset.remove(task)
                self.queue.append(task)
        for task in self.current_taskset:
            if len(removed_tasks) >= max_removal:
                return self.__task_iterable_to_metadata_tuple(removed_tasks)
            if (self.task_metadata[task].state == DirectedTaskState.UNSTARTED
                and self.task_metadata[task].time_elapsed >= config.DIRECTED_TASK_COMPILE_THRESHOLD):
                logger.info(f"Task has not started after so long, removing {task}")
                removed_tasks.add(task)
                self.current_taskset.remove(task)
                
        return self.__task_iterable_to_metadata_tuple(removed_tasks)
    
    def find_task_by_fuzzer_session_id(self, fuzzer_session_id: str) -> Optional[DirectedTask]:
        for task in list(self.current_taskset) + list(self.queue):
            if task.fuzzer_session_id == fuzzer_session_id:
                return task
        return None
                
    def populate_taskset(self) -> list[tuple[DirectedTask, DirectedTaskMetadata]]:
        new_tasks = []
        # get set of cpus currently in use
        current_distribution = [set() for _ in range(self.num_sessions)]
        logger.info("Current taskset")
        for task in self.current_taskset:
            metadata = self.task_metadata[task]
            logger.info(f"{task} {metadata}")
            current_distribution[metadata.node_idx].add(metadata.cpu_idx)
        # for each node, check cpu set
        logging.info(f"CPUs {current_distribution}")
        for node_idx, cpu_set in enumerate(current_distribution):
            # for each directed fuzzer assigned cpu
            for cpu_idx in config.CORES_FOR_DIRECTED:
                # check if there's a free cpu
                if cpu_idx not in cpu_set and len(self.queue) > 0:
                    new_task = self.queue.popleft()
                    if new_task not in self.task_metadata:
                        self.task_metadata[new_task] = DirectedTaskMetadata()
                    # set cpu_idx and node_idx
                    self.task_metadata[new_task].cpu_idx = cpu_idx
                    self.task_metadata[new_task].node_idx = node_idx
                    logger.info(f"adding to taskset {new_task} {self.task_metadata[new_task]}")
                    new_tasks.append(new_task)
        self.current_taskset.update(new_tasks)

        logger.info(f"Queue of pending tasks")
        for task in self.queue:
            logger.info(f"{task}")

        # return to caller in order to actually send the message
        return self.__task_iterable_to_metadata_tuple(new_tasks)
