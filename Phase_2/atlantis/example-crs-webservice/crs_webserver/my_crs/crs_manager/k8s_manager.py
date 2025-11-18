import os
import math
import time
import logging
import redis_lock
from loguru import logger
from typing import Dict, List
from uuid import UUID
import threading

import azure
import kubernetes
from azure.identity import ClientSecretCredential
from azure.mgmt.containerservice import ContainerServiceClient
from my_crs.crs_manager.crs_types import TaskStatus, State
from my_crs.task_server.models.types import TaskDetail
from my_crs.crs_manager.log_config import setup_logger
from kubernetes.utils import create_from_yaml, create_from_dict

from .budget import return_llm_budget, get_llm_spend

setup_logger()

logging.getLogger("azure").setLevel(logging.WARNING)
logging.getLogger("msrest").setLevel(logging.WARNING)
logging.getLogger("redis_lock").setLevel(logging.WARNING)

SLEEP_INTERVAL = 10  # interval to sleep between repeated api checks

# Azure secrets from env variables
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

# Cluster metadata from env variables
CLUSTER_NAME = os.getenv("CLUSTER_NAME")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")


class K8sManager:
    def __init__(self, redis_client, templates):
        credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        self.redis = redis_client
        self.aks_client = ContainerServiceClient(credential, SUBSCRIPTION_ID)
        self.templates = templates

        try:
            kubernetes.config.load_incluster_config()  # For in-cluster execution
        except:
            kubernetes.config.load_kube_config()
        self.k8s_api_client = kubernetes.client.ApiClient()
        self.core_v1_client = kubernetes.client.CoreV1Api()
        self.apps_v1_client = kubernetes.client.AppsV1Api()

    def info(self, msg):
        task_id = os.getenv("TASK_ID")
        logger.info(f"[K8sManager][{task_id}] {msg}")

    def error(self, msg):
        task_id = os.getenv("TASK_ID")
        logger.error(f"[K8sManager][{task_id}] {msg}")

    def __lock(self, node_pool_name):
        self.info(f"Wait for locking {node_pool_name}...")
        return redis_lock.Lock(
            self.redis,
            name=f"azure-lock-{node_pool_name}",
            expire=10,
            auto_renewal=True,
        )

    def __create_node_pool_name(self, key: str) -> str:
        cnt = self.redis.incr(f"{key}_pool_cnt")
        return f"{key}{cnt}"

    def __store_node_pool_name(self, prefix: str, node_pool_name: str):
        task_id = os.getenv("TASK_ID")
        self.redis.set(f"{prefix}_node_pool_name-{task_id}", node_pool_name)

    def __get_node_pool_name(self, prefix: str) -> str:
        task_id = os.getenv("TASK_ID")
        return self.redis.get(f"{prefix}_node_pool_name-{task_id}")

    def create_java_node_pool(self, vm_type: str) -> str:
        return self.__create_node_pool("java", vm_type)

    def create_crs_patch_node_pool(self, vm_type: str) -> str:
        return self.__create_node_pool("patch", vm_type)

    def create_multilang_node_pool(self, vm_type: str) -> str:
        return self.__create_node_pool("multilang", vm_type)

    def create_userspace_node_pool(self, vm_type: str) -> str:
        return self.__create_node_pool("userspace", vm_type)

    def get_userspace_node_pool_name(self) -> str:
        return self.__get_node_pool_name("userspace")

    def get_java_node_pool_name(self) -> str:
        return self.__get_node_pool_name("java")

    def get_multilang_node_pool_name(self) -> str:
        return self.__get_node_pool_name("multilang")

    def get_crs_patch_node_pool_name(self) -> str:
        return self.__get_node_pool_name("patch")

    def create_or_reuse_cp_node_pool(self, task_detail: TaskDetail) -> str:
        # pool_name = self.__find_reusable_cp_node_pool(task_detail)
        # if pool_name is not None:
        #     self.info(f"Reusing cp node pool {pool_name}...")
        #     self.__store_node_pool_name("cp", pool_name)
        #     return pool_name
        self.info("No reusable cp node pool found. Creating a new one...")
        vm_type = os.getenv("CP_MGR_VM_SIZE", "Standard_D32ds_v6")
        if vm_type == "":
            vm_type = "Standard_D32ds_v6"
        pool_name = self.__create_node_pool("cp", vm_type)
        with self.__lock_cp_node_pool():
            self.__set_cp_node_pool_info_under_lock(pool_name, task_detail)
        self.info(f"Created cp node pool {pool_name}.")
        return pool_name

    def __find_reusable_cp_node_pool(self, cur_task_detail: TaskDetail) -> str:
        for idx in range(6 * 5):
            now = int(time.time())
            self.info(
                f"[{idx}th] Try to find a reusable cp node pool... now: {now}"
            )
            with self.__lock_cp_node_pool():
                cp_node_pool_info = self.__list_cp_node_pool_under_lock()
                closest_deadline = None
                for pool_name, task_detail in cp_node_pool_info.items():
                    if task_detail is None:
                        self.__set_cp_node_pool_info_under_lock(
                            pool_name, cur_task_detail
                        )
                        return pool_name
                    else:
                        deadline = int(task_detail.deadline / 1000)
                        if (
                            closest_deadline is None
                            or deadline < closest_deadline
                        ):
                            closest_deadline = deadline
                if closest_deadline == None:
                    break
                if closest_deadline - now > 5 * 60:
                    break
            self.info(
                f"closest_deadline: {closest_deadline}, now: {now}. Almost expired. Sleeping for 10 seconds..."
            )
            time.sleep(10)
        return None

    def __lock_cp_node_pool(self):
        return self.__lock("lock_cp_node_pool")

    def __cp_node_pool_redis_key(self, cp_pool_name: str) -> str:
        return f"info_cp_node_pool_{cp_pool_name}"

    def __set_cp_node_pool_info_under_lock(
        self, cp_pool_name: str, task_detail: TaskDetail
    ):
        key = self.__cp_node_pool_redis_key(cp_pool_name)
        self.redis.set(key, task_detail.model_dump_json())

    def __list_cp_node_pool_under_lock(self):
        keys = self.redis.keys(f"info_cp_node_pool_*")
        ret = {}
        for key in keys:
            info = self.redis.get(key)
            pool_name = key.split("info_cp_node_pool_")[1]
            if info == "":
                ret[pool_name] = None
            else:
                try:
                    ret[pool_name] = TaskDetail.model_validate_json(info)
                except:
                    self.info(
                        f"Invalid task detail in {key} = {info}. Delete {key}"
                    )
                    self.redis.delete(key)
        return ret

    def __release_cp_node_pool(self, node_pool_name: str):
        with self.__lock_cp_node_pool():
            key = self.__cp_node_pool_redis_key(node_pool_name)
            self.redis.set(key, "")

    def __remove_cp_node_pool_if_not_running(
        self,
        node_pool_name: str,
    ) -> bool:
        with self.__lock_cp_node_pool():
            key = self.__cp_node_pool_redis_key(node_pool_name)
            if self.redis.get(key) == "":
                self.redis.delete(key)
                return True
            return False

    def get_cp_node_pool_name(self) -> str:
        return self.__get_node_pool_name("cp")

    def __create_node_pool(self, prefix: str, vm_type: str) -> str:
        while True:
            node_pool_name = self.__create_node_pool_name(prefix)
            self.info(
                f"Creating node pool {node_pool_name}, {vm_type} for {prefix}..."
            )
            self.__store_node_pool_name(prefix, node_pool_name)
            node_pool = {
                "name": node_pool_name,
                "vm_size": vm_type,
                "max_pods": 100,
                "os_disk_type": "Ephemeral",
                "os_type": "Linux",
                "count": 0,  # Initial node count
                "enable_auto_scaling": True,
                "min_count": 0,
                "max_count": 0,
            }
            while True:
                try:
                    self.aks_client.agent_pools.begin_create_or_update(
                        resource_group_name=RESOURCE_GROUP,
                        resource_name=CLUSTER_NAME,
                        agent_pool_name=node_pool_name,
                        parameters=node_pool,
                    ).result()
                    return node_pool_name
                except azure.core.exceptions.ResourceExistsError as e:
                    self.info(
                        f"Node pool {node_pool_name} already exists. Retrying..."
                    )
                    time.sleep(1)
                    break
                except:
                    self.info(f"Retry creating node pool {node_pool_name}...")
                    time.sleep(5)

    def delete_node_pool(self, node_pool_name: str):
        self.info(f"Deleting node pool {node_pool_name}...")
        with self.__lock(node_pool_name):
            while True:
                try:
                    self.info(f"Try to delete node pool {node_pool_name}...")
                    self.aks_client.agent_pools.begin_delete(
                        resource_group_name=RESOURCE_GROUP,
                        resource_name=CLUSTER_NAME,
                        agent_pool_name=node_pool_name,
                    )
                    break
                except azure.core.exceptions.ResourceNotFoundError as e:
                    self.info(f"Node pool {node_pool_name} already deleted.")
                    break
                except:
                    self.info(f"Retry deleting node pool {node_pool_name}...")
                    time.sleep(5)

    def increase_node_pool(self, inc: int, node_pool_name):
        with self.__lock(node_pool_name):
            self.__increase_node_pool_under_lock(inc, node_pool_name)

    def __increase_node_pool_under_lock(self, inc: int, node_pool_name):
        if inc == 0:
            return
        self.info(f"Increase {inc} nodes in node pool '{node_pool_name}'")
        node_pool = self.__get_node_pool(node_pool_name)
        if node_pool is None:
            self.info(
                f"The node pool, {node_pool_name}, is not found. Skipping increase."
            )
            return
        node_pool.count += inc
        node_pool.min_count += inc
        node_pool.max_count += inc
        retry = 0
        while True:
            try:
                self.info(f"Try to increase {inc} nodes..")
                self.aks_client.agent_pools.begin_create_or_update(
                    resource_group_name=RESOURCE_GROUP,
                    resource_name=CLUSTER_NAME,
                    agent_pool_name=node_pool_name,
                    parameters=node_pool,
                ).result()
                break
            except azure.core.exceptions.ResourceExistsError as e:
                time.sleep(SLEEP_INTERVAL)
            except:
                retry += 1
                # an hour: 30 * 120 = 3600 seconds
                if retry > 120:
                    break
                self.info(
                    f"[{retry}] Retry increasing {inc} nodes in node pool '{node_pool_name}'... quota limit..?"
                )
                time.sleep(30)
        self.info(
            f"DONE! Increased {inc} nodes in node pool '{node_pool_name}'"
        )

    def __get_node_pool(self, pool_name: str):
        while True:
            try:
                return self.aks_client.agent_pools.get(
                    RESOURCE_GROUP, CLUSTER_NAME, pool_name
                )
            except azure.core.exceptions.ResourceNotFoundError as e:
                self.info(f"Node pool {pool_name} not found.")
                return None
            except:
                self.info(f"Retry getting node pool {pool_name}...")
                time.sleep(5)

    def __list_node_under_lock(self, label_selector: str, node_pool_name: str):
        label_selector = f"agentpool={node_pool_name},{label_selector}"
        return self.__list_resources_under_lock(
            "node", label_selector, self.core_v1_client.list_node
        )

    def get_idle_nodes(self, node_pool_name: str):
        return self.__list_node_under_lock("!already_labeled", node_pool_name)

    def __read_node(self, node_name: str):
        while True:
            try:
                return self.core_v1_client.read_node(node_name)
            except azure.core.exceptions.ResourceNotFoundError as e:
                self.info(f"Node {node_name} not found.")
                return None
            except:
                self.info(f"Retry reading node {node_name}...")
                time.sleep(5)

    def __check_labeled(self, node, node_labels: Dict[str, str]):
        updated_node = self.__read_node(node.metadata.name)
        if updated_node is None:
            return False
        new_labels = None
        try:
            new_labels = updated_node.metadata.labels
        except:
            return False
        for label in node_labels:
            if node_labels[label] == None:
                if label in new_labels:
                    return False
            else:
                if label not in new_labels:
                    return False
                if node_labels[label] != new_labels[label]:
                    return False
        return True

    def __set_node_labels(self, node, node_labels: Dict[str, str]):
        while True:
            try:
                self.core_v1_client.patch_node(
                    node.metadata.name, {"metadata": {"labels": node_labels}}
                )
            except:
                self.info(
                    f"Retry setting node labels for {node.metadata.name} {node_labels}"
                )
                time.sleep(5)
                continue
            for i in range(20):
                logging.info("Check node is labeled..")
                if self.__check_labeled(node, node_labels):
                    return
                time.sleep(5)

    def add_node_labels(self, node, node_labels: Dict[str, str]):
        node_labels["already_labeled"] = "true"
        old_node_labels = node.metadata.labels or {}
        node_labels.update(old_node_labels)
        self.__set_node_labels(node, node_labels)

    def add_node_labels_for_new_nodes(
        self, node_labels_list: List[Dict[str, str]], node_pool_name: str
    ):
        if len(node_labels_list) == 0:
            return
        while True:
            new_nodes = self.get_idle_nodes(node_pool_name)
            if not new_nodes:
                self.info("No new nodes detected.")
                time.sleep(SLEEP_INTERVAL)
            elif len(new_nodes) < len(node_labels_list):
                logger.info(
                    f"Found {len(new_nodes)} new nodes, Not enough nodes to apply all {len(node_labels_list)} labels."
                )
                time.sleep(SLEEP_INTERVAL)
            else:
                for i, node_labels in enumerate(node_labels_list):
                    new_node = new_nodes[i]
                    self.add_node_labels(new_node, node_labels)
                    self.info(
                        f"Labeled node {new_node.metadata.name} => {node_labels}"
                    )
                    time.sleep(1)
                break

    # K8s deploying
    def deploy_from_template(
        self,
        task_id: UUID,
        template: str,
        node_pool_name: str,
        new_node_count: int,
        *args,
        **kwargs,
    ):
        manifests, node_labels_list = self.templates[template](*args, **kwargs)
        if new_node_count != len(node_labels_list):
            logger.error(
                f"New node count is different from the number of node labels given from {template}."
            )
            return

        with self.__lock(node_pool_name):
            if not self.__is_running(task_id):
                self.info(
                    f"Task {task_id} is not running. Skipping deployment."
                )
                return

            new_node_count = len(node_labels_list)
            # Ensure we have enough nodes
            idle_node_count = len(self.get_idle_nodes(node_pool_name))
            self.info(
                f"Need {new_node_count} nodes but Found {idle_node_count} new nodes."
            )

            new_node_count = max(new_node_count - idle_node_count, 0)
            self.__increase_node_pool_under_lock(new_node_count, node_pool_name)
            self.add_node_labels_for_new_nodes(node_labels_list, node_pool_name)

            for manifest in manifests:
                self.info(f"Deploying...\n{manifest}")
                while True:
                    if not self.__is_running(task_id):
                        self.info(
                            f"Task {task_id} is not running. Skipping deployment."
                        )
                        return
                    try:
                        create_from_dict(self.k8s_api_client, manifest)
                        time.sleep(5)
                        break
                    except Exception as e:
                        self.error(f"Failed to deploy: {str(e)}")
                        time.sleep(10)

    def __is_running(self, task_id: UUID) -> bool:
        key = f"task_{task_id}"
        raw = self.redis.get(key)
        task_status = TaskStatus.model_validate_json(raw)
        return task_status.state == State.Running

    def __get_task_state(self, task_id: UUID) -> State:
        key = f"task_{task_id}"
        raw = self.redis.get(key)
        task_status = TaskStatus.model_validate_json(raw)
        return task_status.state

    def __set_task_state(self, task_id: UUID, state: State):
        key = f"task_{task_id}"
        raw = self.redis.get(key)
        task_status = TaskStatus.model_validate_json(raw)
        task_status.state = state
        self.redis.set(key, task_status.model_dump_json())

    def cancel_task(self, task_id: UUID):
        state = self.__get_task_state(task_id)
        if state in [State.Canceled, State.Cancelling]:
            self.info(f"Task {task_id} already canceled.")
            return
        self.__set_task_state(task_id, State.Cancelling)
        self.__delete_task(task_id)
        self.__set_task_state(task_id, State.Canceled)
        self.redis.decr("running")
        self.redis.incr("canceled")
        self.info(f"Task {task_id} canceled.")

    def __get_llm_url(self, key: str):
        if key.endswith("CRS_java") or key.endswith("CRS_userspace"):
            return os.getenv("LITELLM_USER_JAVA_URL")
        if key.endswith("CRS_multilang"):
            return os.getenv("LITELLM_MULTILANG_URL")
        if key.endswith("CRS_patch"):
            return os.getenv("LITELLM_PATCH_URL")

    def __return_llm_budget(self, task_id: UUID):
        task_id = str(task_id)
        keys = self.redis.keys(f"llm-key-{task_id}-*")
        total_spend = 0
        for key in keys:
            llm_key = self.redis.get(key)
            url = self.__get_llm_url(key)
            spend = get_llm_spend(url, llm_key)
            self.info(f"Spent {spend} LLM budget for {key}")
            total_spend += spend
        return_llm_budget(task_id, math.ceil(total_spend))

    def __delete_task(self, task_id: UUID):
        def delete_fuzzer_pool(label_selector: str):
            self.__delete_deployments_under_lock(label_selector)
            for target_name, node_pool_name in [
                ("multilang", self.get_multilang_node_pool_name()),
                ("java", self.get_java_node_pool_name()),
                ("userspace", self.get_userspace_node_pool_name()),
                ("patch", self.get_crs_patch_node_pool_name()),
            ]:
                self.info(
                    f"[{target_name}] Try to delete node pool {node_pool_name}... (can be None if canceled before creating fuzzing node pool)"
                )
                if node_pool_name in [None, ""]:
                    self.info(
                        f"[{target_name}] {node_pool_name} node pool is not found. (canceled before creation) Skipping deletion."
                    )
                else:
                    self.delete_node_pool(node_pool_name)
            self.__return_llm_budget(task_id)

        label_selector = f"task_id={task_id}"
        t = threading.Thread(target=delete_fuzzer_pool, args=(label_selector,))
        t.start()
        cp_node_pool_name = self.get_cp_node_pool_name()
        self.info(f"Delete node pool {cp_node_pool_name} immediately...")
        self.delete_node_pool(cp_node_pool_name)
        t.join()
        '''
        deleted = self.__delete_pods_under_lock(
            label_selector, cp_node_pool_name
        )
        with self.__lock(cp_node_pool_name):
            if deleted:
                self.__untag_nodes_under_lock(task_id, cp_node_pool_name)
        if deleted:
            self.__release_cp_node_pool(cp_node_pool_name)
        self.__delete_services_under_lock(label_selector)
        t.join()
        if deleted:
            # self.info(f"Try to remove {cp_node_pool_name} after 5 minutes...")
            # time.sleep(60 * 5)
            self.info(f"Try to remove {cp_node_pool_name} immediately...")
            if self.__remove_cp_node_pool_if_not_running(cp_node_pool_name):
                self.delete_node_pool(cp_node_pool_name)
        else:
        '''

    def __delete_pods_under_lock(
        self, label_selector: str, node_pool_name: str
    ):
        self.info(f"Deleting pods for {label_selector} in {node_pool_name}...")
        nodes = self.__list_resources_under_lock(
            "node", f"agentpool={node_pool_name}", self.core_v1_client.list_node
        )
        node_names = [node.metadata.name for node in nodes]
        for node_name in node_names:
            self.info(f"Deleting pods for node {node_name}...")

        def list_pods(label_selector: str):
            pods = self.core_v1_client.list_pod_for_all_namespaces(
                label_selector=label_selector
            )
            ret = []
            for pod in list(pods.items):
                if pod.spec.node_name in node_names:
                    ret.append(pod)
            return ret

        for pod in list_pods(label_selector):
            status = pod.status
            if status is None:
                continue
            self.info(f"Pod {pod.metadata.name} is {status.phase}")
            if status.phase != "Running":
                self.info(
                    f"Pod {pod.metadata.name} is not running. Skipping deletion."
                )
                return False

        self.__delete_resources_under_lock(
            "pod",
            label_selector,
            list_pods,
            self.core_v1_client.delete_namespaced_pod,
            internal_sleep=10,
        )
        return True

    def __delete_deployments_under_lock(self, label_selector: str):
        self.__delete_resources_under_lock(
            "deployment",
            label_selector,
            self.apps_v1_client.list_deployment_for_all_namespaces,
            self.apps_v1_client.delete_namespaced_deployment,
        )

    def __delete_services_under_lock(self, label_selector: str):
        self.__delete_resources_under_lock(
            "service",
            label_selector,
            self.core_v1_client.list_service_for_all_namespaces,
            self.core_v1_client.delete_namespaced_service,
        )

    def __untag_nodes_under_lock(self, task_id: UUID, node_pool_name: str):
        label_selector = f"task_id={task_id}"
        nodes = self.__list_node_under_lock(label_selector, node_pool_name)
        for node in nodes:
            node_labels = dict(node.metadata.labels)
            for key in ["already_labeled", "task_id", "node_type"]:
                node_labels[key] = None
            self.info(f"Untagging node {node.metadata.name}")
            self.__set_node_labels(node, node_labels)

    def __delete_resources_under_lock(
        self,
        resource_type: str,
        label_selector: str,
        list_api,
        delete_api,
        internal_sleep: int = 1,
    ):
        resources = self.__list_resources_under_lock(
            resource_type, label_selector, list_api
        )
        if not resources:
            self.info(
                f"No {resource_type} resources found with {label_selector}."
            )
            return
        resources = list(resources)
        self.info(
            f"Deleting {len(resources)} {resource_type} resources for {label_selector}..."
        )
        while True:
            for resource in resources:
                name = resource.metadata.name
                namespace = resource.metadata.namespace
                try:
                    delete_api(name=name, namespace=namespace)
                    self.info(f"Deleting {name} for {label_selector}...")
                except:
                    self.info(f"Failed to delete {name} for {label_selector}.")
                time.sleep(1)
            time.sleep(internal_sleep)
            resources = self.__list_resources_under_lock(
                resource_type, label_selector, list_api
            )
            if not resources:
                break
            self.info(f"Retry deleting {resource_type} resources...")

    def __list_resources_under_lock(
        self, resource_type: str, label_selector: str, list_api
    ):
        while True:
            try:
                ret = list_api(label_selector=label_selector)
                if isinstance(ret, list):
                    return ret
                else:
                    return ret.items
            except:
                self.info(f"Retry listing {resource_type} resources...")
                time.sleep(5)
