import os
from threading import Lock
import logging

from libatlantis.constants import NODE_NUM

from . import config


logger = logging.getLogger(__name__)

class CoreAllocator:
    def __init__(self, num_nodes: int=1, core_per_node: int=os.cpu_count(), reserved_cores: list[int]=[config.CORE_NUM_FOR_PER_CP_SERVICES] + [config.CORE_NUM_FOR_PER_NODE_SERVICES] * (NODE_NUM - 1)):
        self.lock = Lock()
        self.num_nodes = num_nodes
        self.core_per_node = core_per_node
        if len(reserved_cores) != self.num_nodes:
            logger.error("Number of reserved cores does not match the number of nodes")
            return
        self.matrix = [
            [True] * reserved_cores[i] + [False] * (self.core_per_node - reserved_cores[i]) for i in range(self.num_nodes)
        ]
        logger.info(f"Controller is using {self.num_nodes} nodes")
        for i in range(self.num_nodes):
            logger.info(f"Reserved {reserved_cores[i]} for services in node {i}")
        self.total_non_reserved_cores = sum(self.core_per_node - reserved_cores[i] for i in range(self.num_nodes))
        self.total_reserved_cores = sum(reserved_cores)

    ### not thread safe, do not use directly ###
    def __is_allocated(self, node_idx: int, core_idx: int) -> bool:
        return self.matrix[node_idx][core_idx]
    
    def __is_free(self, node_idx: int, core_idx: int) -> bool:
        return not self.matrix[node_idx][core_idx]
    
    def __allocate_core(self, node_idx: int, core_idx: int):
        if self.__is_allocated(node_idx, core_idx):
            logger.error(f"Node {node_idx}, core {core_idx} is already in use!")
        self.matrix[node_idx][core_idx] = True
    
    def __free_core(self, node_idx: int, core_idx: int):
        if self.__is_free(node_idx, core_idx):
            logger.error(f"Node {node_idx}, core {core_idx} is already free!")
        self.matrix[node_idx][core_idx] = False

    def __find_free_cores_for_one_node(self, node_idx: int, core_num: int) -> list[int]:
        # either find core_num cores or return as much as possible
        result = []
        for i, used in enumerate(self.matrix[node_idx]):
            if not used:
                result.append(i)
                if len(result) == core_num:
                    break
        return result
    
    def get_free_core_num_for_one_node(self, node_idx: int) -> int:
        with self.lock:
            return self.matrix[node_idx].count(False)
    
    def get_free_core_num(self) -> int:
        with self.lock:
            return sum(self.matrix[i].count(False) for i in range(self.num_nodes))

    ### thread safe, call these instead ###
    def allocate_cores(self, core_num: int) -> tuple[int, list[int]]:
        # to keep the load balanced, allocate cores to the node with the least allocated cores
        with self.lock:
            logger.info(f"Trying to allocate {core_num} cores")
            best_node = -1
            best_cores = []

            for node_idx in range(self.num_nodes):
                cores = self.__find_free_cores_for_one_node(node_idx, core_num)
                if len(cores) > len(best_cores):
                    best_node = node_idx
                    best_cores = cores

            cores_to_allocate = min(core_num, len(best_cores))

            # recored the allocation
            for core in best_cores[:cores_to_allocate]:
                self.__allocate_core(best_node, core)

            logger.info(f"Actually allocated {cores_to_allocate} cores to node {best_node}")

            return best_node, best_cores[:cores_to_allocate]
        
    def allocate_core_for_one_node(self, node_idx: int, core_num: int) -> list[int]:
        with self.lock:
            logger.info(f"Trying to allocate {core_num} cores for node {node_idx}")
            cores = self.__find_free_cores_for_one_node(node_idx, core_num)
            if len(cores) < core_num:
                logger.error(f"Not enough cores in node {node_idx}")

            for core in cores:
                self.__allocate_core(node_idx, core)
            logger.info(f"Actually allocated {len(cores)} cores to node {node_idx}")
            return cores
    
    def allocate_total_cores_by_ratio_for_one_node(self, ratio: float) -> tuple[int, list[int]]:
        core_num = int(self.core_per_node * ratio)
        return self.allocate_cores(core_num)
    
    def allocate_free_cores_by_ratio_for_one_node(self, node_idx: int, ratio: float) -> tuple[int, list[int]]:
        free_core_num = self.get_free_core_num_for_one_node(node_idx)
        core_num = int(free_core_num * ratio)
        return self.allocate_cores(core_num)
    
    def free_cores(self, node_idx: int, cores: list[int]):
        with self.lock: 
            for core in cores:
                self.__free_core(node_idx, core)