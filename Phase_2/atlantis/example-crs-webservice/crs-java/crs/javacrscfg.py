import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from javacrs_modules import (
    AIxCCJazzerParams,
    AtlDirectedJazzerParams,
    AtlJazzerParams,
    AtlLibAFLJazzerParams,
    CodeQLParams,
    ConcolicExecutorParams,
    CPUAllocatorParams,
    CrashManagerParams,
    DeepGenParams,
    DictgenParams,
    DiffSchedulerParams,
    ExpKitParams,
    LLMFuzzAugmentorParams,
    LLMPOCGeneratorParams,
    SARIFListenerParams,
    SeedMergerParams,
    SeedSharerParams,
    SinkManagerParams,
    StaticAnalysisParams,
)
from javacrs_modules.utils_leader import CRS_JAVA_POD_NAME
from javacrs_modules.utils_nfs import (
    get_crs_java_sched_flag_path,
    get_planned_crs_java_cfg_path,
)
from pydantic import BaseModel, Field, field_validator


class ModuleParams(BaseModel):
    cpuallocator: CPUAllocatorParams = Field(
        ..., description="CPUAllocator module parameters."
    )
    seedsharer: SeedSharerParams = Field(
        ..., description="SeedSharer module parameters."
    )
    crashmanager: CrashManagerParams = Field(
        ..., description="CrashManager module parameters."
    )
    aixccjazzer: AIxCCJazzerParams = Field(
        ..., description="AIxCCJazzer module parameters."
    )
    atljazzer: AtlJazzerParams = Field(..., description="AtlJazzer module parameters.")
    atldirectedjazzer: AtlDirectedJazzerParams = Field(
        ..., description="AtlDirectedJazzer module parameters."
    )
    atllibafljazzer: AtlLibAFLJazzerParams = Field(
        ..., description="AtlLibAFLJazzer module parameters."
    )
    seedmerger: SeedMergerParams = Field(
        ..., description="SeedMerger module parameters."
    )
    llmpocgen: LLMPOCGeneratorParams = Field(
        ..., description="LLMPOCGenerator module parameters."
    )
    llmfuzzaug: LLMFuzzAugmentorParams = Field(
        ..., description="LLMFuzzAugmentor module parameters."
    )
    concolic: ConcolicExecutorParams = Field(
        ..., description="ConcolicExecutor module parameters."
    )
    codeql: CodeQLParams = Field(..., description="CodeQL module parameters.")
    dictgen: DictgenParams = Field(..., description="Dictgen module parameters.")
    diff_scheduler: DiffSchedulerParams = Field(
        ..., description="DiffScheduler module parameters."
    )
    staticanalysis: StaticAnalysisParams = Field(
        ..., description="StaticAnalysis module parameters."
    )
    sariflistener: SARIFListenerParams = Field(
        ..., description="SARIFListener module parameters."
    )
    sinkmanager: SinkManagerParams = Field(
        ..., description="SinkManager module parameters."
    )
    deepgen: DeepGenParams = Field(..., description="DeepGen module parameters.")
    expkit: ExpKitParams = Field(..., description="ExpKit module parameters.")


class JavaCRSParams(BaseModel):
    class Config:
        title = "JavaCRSParams"
        description = "JavaCRS configuration schema"

    ttl_fuzz_time: int = Field(
        ...,
        description="**Mandatory**, a positive integer for JavaCRS execution time in seconds.",
    )
    workdir: str = Field(
        None,
        description="**Optional**, JavaCRS working directory. If not set, it will be `${CRS_WORKDIR:-/crs-workdir}/worker-${NODE_IDX}` in bash semantics.",
    )
    verbose: bool = Field(
        False, description="**Optional**, verbose log mode. Default is False."
    )
    target_harnesses: Optional[List[str]] = Field(
        None,
        description="**Optional**, if set, only the harness in target list will be ran in this CRS. By default is None, allowing any harness.",
    )
    e2e_check: bool = Field(
        False,
        description="**Optional**, if set, enable e2e check (per 10m) for JavaCRS. Default is False.",
    )
    sync_log: bool = Field(
        False,
        description="**Optional**, if set, enable sync log to NFS right after e2e. Default is False.",
    )
    modules: ModuleParams = Field(..., description="Module parameters.")

    @field_validator("ttl_fuzz_time")
    def ttl_fuzz_time_should_be_positive(cls, v):
        if v <= 0:
            raise ValueError("ttl_fuzz_time must be a positive integer")
        return v


def gen_schema(outfile: str):
    schema = JavaCRSParams.model_json_schema()
    schema_json = json.dumps(schema, indent=2, sort_keys=True)
    with open(outfile, "w") as f:
        f.write(schema_json)


def load_javacrs_cfg(conf_file: Path) -> JavaCRSParams:
    with open(conf_file) as f:
        conf = json.load(f)
        return JavaCRSParams(**conf)


def generalize_conf(conf: dict) -> dict:
    host_ncpu = os.cpu_count()
    if host_ncpu < 4:
        raise ValueError("Host CPU count must be >= 4")
    rescheduled = "target_harnesses" in conf and len(conf["target_harnesses"]) > 1
    if not rescheduled:
        if host_ncpu < 32:
            jazzer_ncpu = int(host_ncpu * 0.8)
            concolic_instance = 0
        elif host_ncpu < 64:
            jazzer_ncpu = int(host_ncpu * 0.8)
            concolic_instance = 1
        elif host_ncpu < 96:
            jazzer_ncpu = int(host_ncpu * 0.85)
            concolic_instance = 1
        else:
            jazzer_ncpu = int(host_ncpu * 0.85)
            concolic_instance = 2
    else:
        # rescheduled module has more than 1 harness (at least 8 cores for concolic, so avoid such case)
        jazzer_ncpu = int(host_ncpu * 0.9)
        concolic_instance = 0
    conf["modules"]["cpuallocator"]["maxncpu"] = host_ncpu
    conf["modules"]["cpuallocator"]["jazzer_ncpu"] = jazzer_ncpu
    if concolic_instance > 0:
        conf["modules"]["concolic"]["num_instance"] = concolic_instance
        if host_ncpu >= 48:
            conf["modules"]["concolic"]["max_mem"] = 32768
        else:
            conf["modules"]["concolic"]["max_mem"] = 16384
    else:
        conf["modules"]["concolic"]["enabled"] = False
    test_round = os.getenv("TEST_ROUND", None)
    if test_round is not None:
        if test_round == "True":
            conf["e2e_check"] = True
            conf["sync_log"] = True
        elif test_round == "False":
            conf["e2e_check"] = False
            conf["sync_log"] = False
    return conf


def get_crs_java_planned_cfg() -> dict | None:
    flag = get_crs_java_sched_flag_path()
    if flag is None or not flag.exists():
        return None

    # NOTE: only merge the planned cfg if the scheduled flag file exists
    pod_id = CRS_JAVA_POD_NAME
    cfg_path = get_planned_crs_java_cfg_path(pod_id)
    if cfg_path is not None and cfg_path.exists():
        with open(cfg_path) as f:
            planned_cfg = json.load(f)
        return planned_cfg
    return None


def update_remote_specified_cfg(local_conf_file: str, remote_conf_file: str):
    with open(local_conf_file) as f:
        local_conf = json.load(f)
    # NOTE: depth-1 shallow merge, update k8s remote default cfg
    with open(remote_conf_file) as f:
        remote_conf = json.load(f)
    local_conf.update(remote_conf)
    # Then update with the planned cfg
    planned_cfg = get_crs_java_planned_cfg()
    if planned_cfg is not None:
        local_conf.update(planned_cfg)
    local_conf = generalize_conf(local_conf)
    with open(local_conf_file, "w") as f:
        json.dump(local_conf, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        if sys.argv[1] == "gen-schema":
            gen_schema(sys.argv[2])
            sys.exit(0)

    elif len(sys.argv) == 4:
        if sys.argv[1] == "merge-crs-cfg":
            update_remote_specified_cfg(sys.argv[2], sys.argv[3])
            sys.exit(0)

    print("Usage: ")
    print(f"      {sys.argv[0]} gen-schema <outfile>")
    print(f"      {sys.argv[0]} merge-crs-cfg <local_conf_file> <remote_conf_file>")
    sys.exit(1)
