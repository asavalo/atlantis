import os
import yaml
import json
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from typing import Dict
from types import SimpleNamespace
from crs_webserver.my_crs.task_server.models.types import TaskDetail

TEMPLATE_DIR = Path(__file__).parent.resolve() / "templates"
CONFIG_DIR = Path(__file__).parent.resolve() / "configs"
REGISTRY = os.getenv("REGISTRY", "ghcr.io/team-atlanta")
TEST_ROUND = os.getenv("TEST_ROUND", "False")

from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()


def to_nice_yaml(value, indent=8):
    yaml_str = yaml.safe_dump(value, default_flow_style=False, indent=2)
    yaml_lines = yaml_str.splitlines()
    nice_yaml = [yaml_lines[0]] + [(" " * indent) + line for line in yaml_lines[1:]]
    return "\n".join(nice_yaml)


def load_templates(directory=TEMPLATE_DIR):
    return {file.stem: file.name for file in directory.glob("*.yaml.j2")}


def load_crs_patch_configs():
    crs_patch_config_file = CONFIG_DIR / "crs-patch.json"
    with open(crs_patch_config_file, "r") as f:
        return json.load(f, object_hook=lambda d: SimpleNamespace(**d))


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


def get_vapi_host(task_id: str) -> str:
    return f"http://cp-manager-{task_id}"


def get_seed_share_dir() -> str:
    return str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "shared_seeds")


def get_shared_log_dir(name: str) -> str:
    return str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / name)


def get_sarif_ana_result_dir() -> str:
    return str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "sarif-analysis-result")


def get_sarif_reachability_dir() -> str:
    return str(
        Path("/shared-crs-fs")
        / os.getenv("TASK_ID")
        / "crs-sarif"
        / "reachability-shared-dir"
    )


def get_sarif_share_dir() -> str:
    return str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "crs-sarif")


def get_crs_java_share_dir() -> str:
    return str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "crs-java")


def get_crs_userspace_share_dir() -> str:
    return str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "crs-userspace")


def add_otel_env(env, name, category, harness=None):
    add = {
        "AIXCC_OTLP_ENDPOINT": os.getenv("AIXCC_OTLP_ENDPOINT"),
        "OTEL_EXPORTER_OTLP_HEADERS": os.getenv("OTEL_EXPORTER_OTLP_HEADERS"),
        "OTEL_EXPORTER_OTLP_PROTOCOL": os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
        "CRS_TASK_METADATA_JSON": os.getenv("CRS_TASK_METADATA_JSON"),
        "CRS_SERVICE_NAME": name,
        "CRS_ACTION_CATEGORY": category,
        "TEST_ROUND": TEST_ROUND,
    }
    if harness != None:
        add["CRS_HARNESS_NAME"] = harness
    for key in add:
        env[key] = add[key]


def crs_multilang_cp_levels(
    task_detail: TaskDetail,
    tarball_dir: Path,
):
    task_id = str(task_detail.task_id)
    proj_name = task_detail.project_name

    node_type = f"crs-multilang-cp-lvl-{task_id}"
    selector = {
        "task_id": task_id,
        "node_type": node_type,
    }

    params = {
        "name": f"crs-multilang-cp-lvl-{task_id}",
        "image_version": os.getenv("IMAGE_VERSION"),
        "task_id": task_id,
        "node_type": node_type,
        "registry": REGISTRY,
        "env_vars": {
            "TARBALL_DIR": str(tarball_dir),
            "CRS_TARGET": proj_name,
        },
        "env_vars_cov_runner": {
            "FUZZING_ENGINE": "libfuzzer",
            "SANITIZER": "address",
            "RUN_FUZZER_MODE": "interactive",
            "HELPER": "True",
            "CRS_TARGET": proj_name,
            "CRS_INTERACTIVE": "True",
            "TARBALL_DIR": str(tarball_dir),
            "SEED_SHARE_DIR": get_seed_share_dir(),
        },
        "node_selector": selector,
    }
    return (
        list(yaml.safe_load_all(generate_manifest("crs-multilang-cp-lvl", params))),
        [selector],
    )


def crs_multilang_nodes(
    task_detail: TaskDetail,
    tarball_dir: Path,
    harness_names: list[str],
    llm_key: str,
    sanitizer: str = "address",
):
    task_id = str(task_detail.task_id)
    proj_name = task_detail.project_name
    manifests = []
    selectors = []
    idx = 0
    for harness_name in harness_names:
        manifest, selector = crs_multilang_node(
            task_id, idx, tarball_dir, proj_name, harness_name, sanitizer, llm_key
        )
        manifests.append(manifest)
        selectors.append(selector)
        idx += 1
    return manifests, selectors


def get_dictgen_redis_url():
    return f"redis://cp-manager-{os.getenv('TASK_ID')}:9500"


def crs_multilang_node(
    task_id: str,
    idx: int,
    tarball_dir: Path,
    proj_name: str,
    harness_name: str,
    sanitizer: str,
    llm_key: str,
):
    node_type = f"crs-multilang-{idx}"
    selector = {
        "task_id": task_id,
        "node_type": node_type,
    }

    crs_config = {
        "target_harnesses": [harness_name],
        # "others": {
        # "input_gens": [
        # "given_fuzzer",
        # ],
        # },
    }

    crs_config_path = tarball_dir / f"{idx}.json"
    crs_config_path.write_text(json.dumps(crs_config))

    params = {
        "name": f"crs-multilang-{task_id}-{idx}",
        "image_version": os.getenv("IMAGE_VERSION"),
        "task_id": task_id,
        "node_type": node_type,
        "registry": REGISTRY,
        "env_vars": {
            "LITELLM_URL": os.getenv("LITELLM_MULTILANG_URL"),
            "LITELLM_KEY": llm_key,
            "CODE_INDEXER_REDIS_URL": f"cp-manager-{task_id}",
            "DICTGEN_REDIS_URL": get_dictgen_redis_url(),
            "VAPI_HOST": get_vapi_host(task_id),
            "FUZZING_ENGINE": "libfuzzer",
            "SANITIZER": sanitizer,
            "RUN_FUZZER_MODE": "interactive",
            "HELPER": "True",
            "CRS_TARGET": proj_name,
            "CRS_INTERACTIVE": "True",
            "TARBALL_DIR": str(tarball_dir),
            "CRS_CONFIG": crs_config_path,
            "SEED_SHARE_DIR": get_seed_share_dir(),
            "SHARED_DIR": get_shared_log_dir("crs-multilang-log"),
            "JOERN_URL": f"crs-multilang-cp-lvl-{task_id}",
            "LSP_SERVER_URL": f"cp-manager-{task_id}:3303",
        },
        "node_selector": selector,
    }

    add_otel_env(params["env_vars"], "crs-multilang", "fuzzing", harness_name)

    return yaml.safe_load(generate_manifest("crs-multilang", params)), selector


def crs_java_nodes(
    task_detail: TaskDetail,
    download_tdir: Path,
    javacrs_tdir: Path,
    harness_names: list[str],
    llm_key: str,
    sanitizer: str = "address",
):
    task_id = str(task_detail.task_id)
    proj_name = task_detail.project_name
    manifests = []
    selectors = []
    idx = 0
    for harness_name in harness_names:
        manifest, selector = crs_java_node(
            task_id,
            idx,
            download_tdir,
            javacrs_tdir,
            proj_name,
            harness_name,
            sanitizer,
            llm_key,
        )
        manifests.append(manifest)
        selectors.append(selector)
        idx += 1
    return manifests, selectors


def crs_java_node(
    task_id: str,
    idx: int,
    download_tdir: Path,
    javacrs_tdir: Path,
    proj_name: str,
    harness_name: str,
    sanitizer: str,
    llm_key: str,
):
    node_type = f"crs-java-{idx}"
    selector = {
        "task_id": task_id,
        "node_type": node_type,
    }

    crs_config = {
        "target_harnesses": [harness_name],
    }

    crs_config_path = javacrs_tdir / f"{idx}.json"
    crs_config_path.write_text(json.dumps(crs_config))

    extra_volumes = [
        {"name": "crs-workdir", "emptyDir": {}},
        {"name": "dshm", "emptyDir": {"medium": "Memory", "sizeLimit": "32Gi"}},
    ]

    extra_volume_mounts = [
        {"name": "dshm", "mountPath": "/dev/shm"},
        {"name": "crs-workdir", "mountPath": "/crs-workdir"},
    ]

    params = {
        "name": f"crs-java-{task_id}-{idx}",
        "image_version": os.getenv("IMAGE_VERSION"),
        "task_id": task_id,
        "node_type": node_type,
        "registry": REGISTRY,
        "env_vars": {
            "AIXCC_LITELLM_HOSTNAME": os.getenv("LITELLM_USER_JAVA_URL"),
            "LITELLM_URL": os.getenv("LITELLM_USER_JAVA_URL"),
            "LITELLM_KEY": llm_key,
            "CRS_TARGET": proj_name,
            "FUZZING_ENGINE": "libfuzzer",
            "HELPER": "True",
            "JAVACRS_CFG": crs_config_path,
            "JAVACRS_TARBALL_DIR": str(javacrs_tdir.resolve()),
            "RUN_FUZZER_MODE": "interactive",
            "SANITIZER": sanitizer,
            "TARBALL_DIR": str(download_tdir.resolve()),
            "TARBALL_FS_DIR": str(
                (Path("/tarball-fs") / os.getenv("TASK_ID")).resolve()
            ),
            "VAPI_HOST": get_vapi_host(task_id),
            "SEED_SHARE_DIR": get_seed_share_dir(),
            "SARIF_ANA_RESULT_DIR": get_sarif_ana_result_dir(),
            "SARIF_REACHABILIY_SHARE_DIR": get_sarif_reachability_dir(),
            "SARIF_SHARE_DIR": get_sarif_share_dir(),
            "CRS_JAVA_SHARE_DIR": get_crs_java_share_dir(),
            "CPMETA_REDIS_URL": f"redis://cp-manager-{task_id}:9505",
            "DICTGEN_REDIS_URL": get_dictgen_redis_url(),
        },
        "node_selector": selector,
        "extra_volumes": extra_volumes,
        "extra_volume_mounts": extra_volume_mounts,
    }
    add_otel_env(params["env_vars"], "crs-java", "fuzzing", harness_name)

    return yaml.safe_load(generate_manifest("crs-java", params)), selector


def crs_patch_nodes(
    task_detail: TaskDetail,
    download_tarball_dir: Path,
    llm_key: str,
    language: str,
):
    manifests, selectors = crs_patch_main_node(
        str(task_detail.task_id),
        task_detail.project_name,
        download_tarball_dir,
        llm_key,
        language,
    )

    for subconfig in load_crs_patch_configs():
        sub_manifest, sub_selector = crs_patch_sub_node(
            str(task_detail.task_id),
            task_detail.project_name,
            download_tarball_dir,
            llm_key,
            language,
            subconfig,
        )
        manifests.extend(sub_manifest)
        selectors.extend(sub_selector)
    return manifests, selectors


def crs_patch_main_node(
    task_id: str,
    proj_name: str,
    download_tarball_dir: Path,
    llm_key: str,
    language: str,
):
    node_name = f"crs-patch-{task_id}"
    node_type = node_name
    selector = {
        "task_id": task_id,
        "node_type": node_type,
    }
    params = {
        "name": node_name,
        "image_version": os.getenv("IMAGE_VERSION"),
        "task_id": task_id,
        "node_type": node_type,
        "registry": REGISTRY,
        "env_vars": {
            "LITELLM_API_BASE": os.getenv("LITELLM_PATCH_URL"),
            "LITELLM_API_KEY": llm_key,
            "VAPI_HOST": get_vapi_host(task_id),
            "CRS_TARGET": proj_name,
            "TARBALL_DIR": str(download_tarball_dir),
            "REGISTRY": REGISTRY,
            "IMAGE_VERSION": os.getenv("IMAGE_VERSION"),
            "SEED_SHARE_DIR": get_seed_share_dir(),
            "VLLM_API_BASE": os.getenv("VLLM_API_BASE"),
            "ADAPTER_API_BASE": os.getenv("ADAPTER_API_BASE"),
            "PROJECT_LANGUAGE": language,
            "TASK_ID": task_id,
        },
        "node_selector": selector,
    }
    add_otel_env(params["env_vars"], "crs-patch", "patch_generation")
    return list(yaml.safe_load_all(generate_manifest("crs-patch-main", params))), [
        selector
    ]


def crs_patch_sub_node(
    task_id: str,
    proj_name: str,
    download_tarball_dir: Path,
    llm_key: str,
    language: str,
    subconfig: SimpleNamespace,
):
    node_name = f"crs-patch-sub-{subconfig.id}-{task_id}"
    node_type = node_name
    selector = {
        "task_id": task_id,
        "node_type": node_type,
    }
    params = {
        "name": node_name,
        "image_version": os.getenv("IMAGE_VERSION"),
        "task_id": task_id,
        "node_type": node_type,
        "registry": REGISTRY,
        "sub_node_id": subconfig.id,
        "env_vars": {
            "LITELLM_API_BASE": os.getenv("LITELLM_PATCH_URL"),
            "LITELLM_API_KEY": llm_key,
            "VAPI_HOST": get_vapi_host(task_id),
            "CRS_TARGET": proj_name,
            "TARBALL_DIR": str(download_tarball_dir),
            "REGISTRY": REGISTRY,
            "IMAGE_VERSION": os.getenv("IMAGE_VERSION"),
            "SEED_SHARE_DIR": get_seed_share_dir(),
            "VLLM_API_BASE": os.getenv("VLLM_API_BASE"),
            "ADAPTER_API_BASE": os.getenv("ADAPTER_API_BASE"),
            "PROJECT_LANGUAGE": language,
            "APP_NAME": subconfig.id,
            "APP_MODULE": subconfig.module,
        },
        "node_selector": selector,
    }
    add_otel_env(params["env_vars"], "crs-patch", "patch_generation")
    return list(yaml.safe_load_all(generate_manifest("crs-patch-sub", params))), [
        selector
    ]


def crs_userspace_nodes(
    task_detail: TaskDetail,
    tar_dir: Path,
    node_num: int,
    llm_key: str,
):
    task_id = str(task_detail.task_id)
    proj_name = task_detail.project_name
    focus = task_detail.focus
    manifests = []
    selectors = []
    node_idx = 0
    for node_idx in range(node_num):
        crs_manifests, selector = crs_userspace_node(
            task_id,
            node_idx,
            tar_dir,
            proj_name,
            focus,
            node_num,
            llm_key,
            int(task_detail.deadline / 1000),
        )
        manifests.extend(crs_manifests)
        selectors.append(selector)
    return manifests, selectors


def crs_userspace_node(
    task_id: str,
    node_idx: int,
    tar_dir: Path,
    proj_name: str,
    focus: str,
    node_num: int,
    llm_key: str,
    task_deadline: int,
):
    selector = {
        "task_id": task_id,
        "node_type": f"crs-userspace-{node_idx}",
    }
    shared_volumes = [
        {
            "name": "shared-crs-fs-volume",
            "persistentVolumeClaim": {"claimName": "shared-crs-fs"},
        },
        {
            "name": "tarball-fs-volume",
            "persistentVolumeClaim": {"claimName": "tarball-fs"},
        },
    ]
    shared_volume_mounts = [
        {"name": "shared-crs-fs-volume", "mountPath": "/shared-crs-fs"},
        {"name": "tarball-fs-volume", "mountPath": "/tarball-fs", "readOnly": True},
    ]
    extra_volumes = [
        {"name": "crs-scratch", "emptyDir": {}},
        {"name": "artifacts", "emptyDir": {}},
        {"name": "oss-fuzz", "emptyDir": {}},
        {"name": "src", "emptyDir": {}},
        {"name": "dshm", "emptyDir": {"medium": "Memory", "sizeLimit": "32Gi"}},
        {"name": "tmpfs", "emptyDir": {"medium": "Memory", "sizeLimit": "32Gi"}},
        {"name": "ipc-sock", "emptyDir": {}},
    ]
    extra_volume_mounts = [
        {"name": "crs-scratch", "mountPath": "/crs_scratch"},
        {"name": "artifacts", "mountPath": "/artifacts"},
        {"name": "oss-fuzz", "mountPath": "/oss_fuzz"},
        {"name": "src", "mountPath": "/src"},
    ]
    tmpfs_volume_mounts = [{"name": "tmpfs", "mountPath": "/tmpfs"}]
    ipc_sock_mounts = [{"name": "ipc-sock", "mountPath": "/tmp/ipc"}]
    dshm_volume_mounts = [{"name": "dshm", "mountPath": "/dev/shm"}]

    name = f"crs-userspace-{task_id}-{node_idx}"
    kafka_service_name = f"crs-userspace-{task_id}-0"
    params = {
        "name": name,
        "task_id": task_id,
        "node_idx": str(node_idx),
        "node_type": f"crs-userspace-{node_idx}",
        "registry": REGISTRY,
        "image_version": os.getenv("IMAGE_VERSION"),
        "kafka_service_name": kafka_service_name,
        "env_vars": {
            "CRS_TAR_DIR": str(tar_dir),
            "CRS_FOCUS": str(focus),
            "CRS_TARGET_NAME": proj_name,
            "AIXCC_LITELLM_HOSTNAME": os.getenv("LITELLM_USER_JAVA_URL"),
            "IMAGE_VERSION": os.getenv("IMAGE_VERSION"),
            "LITELLM_KEY": llm_key,
            "CRS_SCRATCH_SPACE": "/crs_scratch",
            "CRS_OSS_FUZZ_PATH": "/oss_fuzz",
            "CRS_TARGET_SRC_PATH": "/src",
            "SHARED_CRS_SPACE": get_crs_userspace_share_dir(),
            "ATLANTIS_LARGE_DATA": f"{get_crs_userspace_share_dir()}/large_data",
            "ATLANTIS_ARTIFACTS": "/artifacts",
            "ENSEMBLER_TMPFS": "/tmpfs",
            "CODE_BROWSER_ADDRESS": f"{name}:50051",
            "IN_K8S": "true",
            "NODE_NUM": str(node_num),
            "NODE_IDX": str(node_idx),
            "VAPI_HOST": get_vapi_host(task_id),
            "SEED_SHARE_DIR": get_seed_share_dir(),
            "REACHABILITY_SHARE_DIR": get_sarif_reachability_dir(),
            "SARIF_SHARE_DIR": get_sarif_ana_result_dir(),
            "REGISTRY": f"{REGISTRY}/crs-userspace",
            "TASK_ID": task_id,
            "TASK_DEADLINE": str(task_deadline),
            "EPOCH_DURATION": "1800",
        },
        "kafka_env_vars": {},
        "node_selector": selector,
        "shared_volumes": shared_volumes,
        "shared_volume_mounts": shared_volume_mounts,
        "extra_volumes": extra_volumes,
        "extra_volume_mounts": extra_volume_mounts,
        "ipc_sock_mounts": ipc_sock_mounts,
        "dshm_volume_mounts": dshm_volume_mounts,
        "tmpfs_volume_mounts": tmpfs_volume_mounts,
    }
    add_otel_env(params["env_vars"], "crs-userspace", "fuzzing")

    if node_idx == 0:
        return (
            list(
                yaml.safe_load_all(
                    generate_manifest("crs-userspace-controller", params)
                )
            ),
            selector,
        )
    else:
        return (
            list(yaml.safe_load_all(generate_manifest("crs-userspace-worker", params))),
            selector,
        )


def crs_sarif_nodes(
    proj_name: str,
    task_id: str,
    tarball_dir: Path,
    harness_names: str,
    language: str,
    llm_key: str,
):
    node_type = f"crs-sarif"
    selector = {
        "task_id": task_id,
        "node_type": f"crs-sarif-{task_id}",
    }

    shared = str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "shared_seeds")

    params = {
        "name": f"crs-sarif-{task_id}",
        "image_version": os.getenv("IMAGE_VERSION"),
        "task_id": task_id,
        "node_type": node_type,
        "registry": REGISTRY,
        "env_vars": {
            "REGISTRY": REGISTRY,
            "IMAGE_VERSION": os.getenv("IMAGE_VERSION"),
            # builder
            # "OSS_FUZZ_DIR": "/oss-fuzz",
            # "TARBALL_DIR": str(tarball_dir),
            "REGISTRY": os.getenv("REGISTRY"),
            "PROJECT_NAME": proj_name,
            "PROJECT_LANGUAGE": "jvm" if language in ["java", "jvm"] else "c",
            "HARNESS_NAMES": ":".join(harness_names),
            "SOURCE_DIR": "/sarif_src_dir",
            "BUILDER_OUT_DIR": "/sarif_out_dir",
            # "BUILD_SHARED_DIR": str(build_shared_dir),
            "SVF_MODE": "ander",
            "RUN_GDB_SH_PATH": "/app/bin/scripts/run_gdb.sh",
            "SVF_PARALLEL": "False",
            "SVF_MAX_WORKERS": "1",
            # "SVF_PARALLEL": "True",
            # "SVF_MAX_WORKERS": "4",
            "VAPI_HOST": get_vapi_host(task_id),
            "CRS_TARGET": proj_name,
            "CRS_SARIF_REDIS_URL": "redis://localhost:6379",
            "CRS_MODE": "debug",
            "BUILD_DIR": str(Path("/sarif-workspace") / "build"),
            "OUT_DIR": str(Path("/sarif-workspace") / "out"),
            "SRC_DIR": str(Path("/sarif-workspace") / "source"),
            "PROJECT_NAME": proj_name,
            "PROJECT_LANGUAGE": language,
            "CP_PROJ_PATH": str(
                Path("/sarif-workspace")
                / "source"
                / "fuzz-tooling"
                / "projects"
                / proj_name
            ),
            # "CP_SRC_PATH": str(Path("/shared-crs-fs") / os.getenv("TASK_ID") / "crs-sarif" / "out" / "src"),
            "SHARED_ROOT_DIR": str(
                Path("/shared-crs-fs") / os.getenv("TASK_ID") / "crs-sarif"
            ),
            # WRITE
            "REACHABILITY_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "crs-sarif"
                / "reachability-shared-dir"
            ),
            "CALL_TRACE_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "crs-sarif"
                / "call-trace-shared-dir"
            ),
            "CRS_SARIF_TRACER_TRACE_OUTPUTDIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "crs-sarif"
                / "call-trace-shared-dir"
            ),
            "COVERAGE_REQUEST_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "shared_seeds"
                / "cov_request"
            ),
            "ORIGINAL_SARIF_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "crs-sarif"
                / "original-sarif-shared-dir"
            ),
            # READ
            "TARBALL_DIR": str(tarball_dir),
            "BUILD_SHARED_DIR": str(
                Path("/tarball-fs") / os.getenv("TASK_ID") / "crs-sarif" / "out"
            ),
            "MULTILANG_BUILD_DIR": str(
                Path("/tarball-fs") / os.getenv("TASK_ID") / "crs-multilang"
            ),
            "COVERAGE_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "shared_seeds"
                / "coverage_shared_dir"
            ),
            "CORPUS_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "shared_seeds"
                / "crs-multilang"
            ),
            "CRS_SARIF_TRACER_CORPUS_DIRECTORY": str(
                Path("/shared-crs-fs") / os.getenv("TASK_ID") / "shared_seeds"
            ),
            "JAVA_CP_METADATA_PATH": get_crs_java_share_dir(),
            "FUZZING_ENGINE": "libfuzzer",
            "HELPER": "True",
            "FUZZING_LANGUAGE": language,
            "POCGEN_ROOT_DIR": "/app/llm-poc-gen",
            "POCGEN_JOERN_DIR": "/opt/joern",
            "POCGEN_OUTPUT_DIR": "/app/llm-poc-gen/output",
            "POCGEN_CP_NAME": proj_name,
            "POCGEN_WORK_DIR": str(
                Path("/sarif-workspace")
                / "source"
                / "fuzz-tooling"
                / "projects"
                / proj_name
            ),
            "POCGEN_REPO_SRC_PATH": str(Path("/sarif-workspace") / "source"),
            "POCGEN_DEBUG_SRC_DIR": str(Path("/sarif-workspace") / "build" / "cpg_src"),
            "POCGEN_DEBUG_BIN_DIR": str(Path("/sarif-workspace") / "build" / "debug"),
            "POCGEN_SHARED_DIR": str(
                Path("/shared-crs-fs")
                / os.getenv("TASK_ID")
                / "shared_seeds"
                / "crs-sarif"
            ),
            "LITELLM_KEY": llm_key,
            "AIXCC_LITELLM_HOSTNAME": os.getenv("LITELLM_PATCH_URL"),
            "OPENAI_API_KEY": llm_key,
            "OPENAI_BASE_URL": os.getenv("LITELLM_PATCH_URL"),
        },
        "node_selector": selector,
    }

    add_otel_env(params["env_vars"], "crs-sarif", "program_analysis")

    return (
        list(yaml.safe_load_all(generate_manifest("crs-sarif", params))),
        [selector],
    )


TEMPLATES = {
    "crs-multilang-nodes": crs_multilang_nodes,
    "crs-java-nodes": crs_java_nodes,
    "crs-patch-nodes": crs_patch_nodes,
    "crs-userspace-nodes": crs_userspace_nodes,
    "crs-sarif-nodes": crs_sarif_nodes,
    "crs-multilang-cp-levels": crs_multilang_cp_levels,
}
