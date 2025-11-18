import os
import yaml
from loguru import logger
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from typing import Dict

from my_crs.task_server.models.types import TaskDetail
from my_crs.crs_manager.log_config import setup_logger

setup_logger()

# CRS auth
CRS_KEY_ID = os.getenv("CRS_KEY_ID")
CRS_KEY_TOKEN = os.getenv("CRS_KEY_TOKEN")
CRS_CONTROLLER_KEY_ID = os.getenv("CRS_CONTROLLER_KEY_ID")
CRS_CONTROLLER_KEY_TOKEN = os.getenv("CRS_CONTROLLER_KEY_TOKEN")

# Azure secrets from env variables
TENANT_ID = os.getenv("AZURE_TENANT_ID")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

# Cluster metadata from env variables
CLUSTER_NAME = os.getenv("CLUSTER_NAME")
RESOURCE_GROUP = os.getenv("RESOURCE_GROUP")

REGISTRY = os.getenv("REGISTRY", "ghcr.io/team-atlanta")
TEMPLATE_DIR = Path(__file__).parent.resolve() / "templates"
TEST_ROUND = os.getenv("TEST_ROUND", "False")


def to_nice_yaml(value, indent=8):
    yaml_str = yaml.safe_dump(value, default_flow_style=False, indent=2)
    yaml_lines = yaml_str.splitlines()
    nice_yaml = [yaml_lines[0]] + [(" " * indent) + line for line in yaml_lines[1:]]
    return "\n".join(nice_yaml)


def load_templates(directory=TEMPLATE_DIR):
    return {file.stem: file.name for file in directory.glob("*.yaml.j2")}


def generate_manifest(manifest_type, params, templates=None):
    if templates is None:
        templates = load_templates()

    # jinja2 env
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    env.filters["to_nice_yaml"] = to_nice_yaml

    if not manifest_type.endswith(".yaml") and not manifest_type.endswith(".yml"):
        manifest_type = manifest_type + ".yaml"
    if manifest_type not in templates:
        logger.error(f"Template {manifest_type} does not exist.")
        return None

    return env.get_template(templates[manifest_type]).render(params)


def cp_manager_node(
    task_detail: TaskDetail,
    cp_node_pool_name: str,
    llm_key_for_crs_sarif: str,
) -> list:
    task_id = str(task_detail.task_id)
    node_selector = {
        "task_id": task_id,
        "node_type": f"cp-manager-{task_id}",
    }
    return cp_manager(task_detail, node_selector, cp_node_pool_name, llm_key_for_crs_sarif), [node_selector]


def cp_manager(
    task_detail: TaskDetail,
    node_selector: Dict[str, str],
    cp_node_pool_name: str,
    llm_key_for_crs_sarif: str,
):
    task_id = str(task_detail.task_id)
    env_vars = {
        "TASK_ID": task_id,
        "TASK_PROJECT_NAME": task_detail.project_name,
        "TASK_MODE": task_detail.type.value,
        "COMPETITION_URL": os.getenv("COMPETITION_URL"),
        "COMPETITION_API_KEY_ID": os.getenv("COMPETITION_API_KEY_ID"),
        "COMPETITION_API_KEY_TOKEN": os.getenv("COMPETITION_API_KEY_TOKEN"),
        "LITELLM_MASTER_KEY": os.getenv("LITELLM_MASTER_KEY"),
        "CRS_KEY_ID": CRS_KEY_ID,
        "CRS_KEY_TOKEN": CRS_KEY_TOKEN,
        "CRS_CONTROLLER_KEY_ID": CRS_CONTROLLER_KEY_ID,
        "CRS_CONTROLLER_KEY_TOKEN": CRS_CONTROLLER_KEY_TOKEN,
        "CODE_INDEXER_REDIS_URL": f"cp-manager-{task_id}",
        "CRS_REDIS_ENDPOINT": "redis://crs-webapp:6379",
        "AZURE_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
        "AZURE_CLIENT_ID": CLIENT_ID,
        "AZURE_CLIENT_SECRET": CLIENT_SECRET,
        "AZURE_TENANT_ID": TENANT_ID,
        "CLUSTER_NAME": CLUSTER_NAME,
        "RESOURCE_GROUP": RESOURCE_GROUP,
        "REGISTRY": REGISTRY,
        "IMAGE_VERSION": os.getenv("IMAGE_VERSION"),
        "LITELLM_USER_JAVA_URL": os.getenv("LITELLM_USER_JAVA_URL"),
        "LITELLM_PATCH_URL": os.getenv("LITELLM_PATCH_URL"),
        "LITELLM_MULTILANG_URL": os.getenv("LITELLM_MULTILANG_URL"),
        "VLLM_API_BASE": os.getenv("VLLM_API_BASE"),
        "ADAPTER_API_BASE": os.getenv("ADAPTER_API_BASE"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "AIXCC_OTLP_ENDPOINT": os.getenv("AIXCC_OTLP_ENDPOINT"),
        "OTEL_EXPORTER_OTLP_HEADERS": os.getenv("OTEL_EXPORTER_OTLP_HEADERS"),
        "OTEL_EXPORTER_OTLP_PROTOCOL": os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
        "CRS_TASK_METADATA_JSON": f"/tarball-fs/{task_id}/metadata.json",
        "CRS_SERVICE_NAME": "cp-manager",
        "CRS_ACTION_CATEGORY": "building",
        "CRS_ACTION_NAME": "cp_manager",
        "TOTAL_VCPU": os.getenv("TOTAL_VCPU"),
        "TOTAL_LLM_BUDGET": os.getenv("TOTAL_LLM_BUDGET"),
        "MAX_TASK_CNT": os.getenv("MAX_TASK_CNT"),
        "USERSPACE_NODE_SIZE": os.getenv("USERSPACE_NODE_SIZE", "64"),
        "USERSPACE_MAX_NODE_CNT": os.getenv("USERSPACE_MAX_NODE_CNT", "4"),
        "CP_NODE_POOL_NAME": cp_node_pool_name,
        "LITELLM_KEY_CRS_SARIF": llm_key_for_crs_sarif,
        "CP_MGR_VM_SIZE": os.getenv("CP_MGR_VM_SIZE", "Standard_D32ds_v6"),
        "CRS_PATCH_VM_SIZE": os.getenv("CRS_PATCH_VM_SIZE", "Standard_D32ds_v6"),
        "QUOTA_PER_CP": os.getenv("QUOTA_PER_CP", "1000"),
        "TEST_ROUND": TEST_ROUND,
    }
    for name in ["CRS_patch", "CRS_java", "CRS_multilang", "CRS_userspace"]:
        key = f"LLM_budget_{name}"
        budget = os.getenv(key)
        env_vars[key] = budget

    params = {
        "node_type": f"cp-manager-{task_id}",
        "image_version": os.getenv("IMAGE_VERSION"),
        "registry": REGISTRY,
        "task_id": task_id,
        "name": f"cp-manager-{task_id}",
        "crs": "cp-manager",
        "dedicated_node": False,
        "env_vars": env_vars,
        "node_selector": node_selector,
    }
    return list(yaml.safe_load_all(generate_manifest("cp-manager", params)))


# Template functions dict
TEMPLATES = {
    "cp-manager-node": cp_manager_node,
}
