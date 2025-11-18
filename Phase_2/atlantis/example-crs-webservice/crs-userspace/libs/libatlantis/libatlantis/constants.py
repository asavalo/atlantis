import os as _os
from pathlib import Path as _Path


IN_K8S = _os.environ.get("IN_K8S", "false").lower() == "true"

CRS_SCRATCH_DIR = _Path(_os.environ.get("CRS_SCRATCH_SPACE", "/crs_scratch")).resolve()
ARTIFACTS_DIR = _Path(_os.environ.get("ATLANTIS_ARTIFACTS", "/artifacts")).resolve(strict=False)
LARGE_DATA_DIR = _Path(_os.environ.get("ATLANTIS_LARGE_DATA", "/large_data")).resolve(strict=False)
SHARED_CRS_DIR = _Path(_os.environ.get("SHARED_CRS_SPACE", "/shared-crs-fs")).resolve()
KAFKA_SERVER_ADDR = _os.environ.get("KAFKA_SERVER_ADDR", "kafka:9092")

REGISTRY = _os.environ.get("REGISTRY", "ghcr.io/team-atlanta")
IMAGE_VERSION = _os.environ.get("IMAGE_VERSION", "latest")

NODE_NUM = int(_os.environ.get("NODE_NUM", 1))
NODE_CPU_CORES = int(_os.environ.get("NODE_CPU_CORES", _os.cpu_count()))

CP_CONFIG_TOPIC = "cp_config"
HELLO_TOPIC = "hello"
FILE_OPS_TOPIC = "file_ops"
FILE_OPS_RESPONSE_TOPIC = "file_ops_response"

OSV_ANALYZER_RESULTS_TOPIC = "osv_analyzer_results"

HARNESS_BUILDER_REQUEST_TOPIC = "harness_builder_build_request"
HARNESS_BUILDER_RESULT_TOPIC = "harness_builder_build_result"

FUZZER_RUN_REQUEST_TOPIC = "fuzzer_run_request"
FUZZER_RUN_RESPONSE_TOPIC = "fuzzer_run_response"
FUZZER_STOP_REQUEST_TOPIC = "fuzzer_stop_request"
FUZZER_STOP_RESPONSE_TOPIC = "fuzzer_stop_response"
FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC = "fuzzer_launch_announcement"
HARNESS_PRIORITIZATION_TOPIC = "harness_prioritization"

LLM_MUTATOR_REQUEST_TOPIC = "llm_mutator_request"
LLM_MUTATOR_RESPONSE_TOPIC = "llm_mutator_response"


FUZZER_SEED_SUGGESTIONS_TOPIC = "fuzzer_seed_suggestions"
CRASHING_SEED_SUGGESTIONS_TOPIC = "crashing_seed_suggestions"

DEEPGEN_REQUEST_TOPIC = "deepgen_request"
DEEPGEN_RESPONSE_TOPIC = "deepgen_response" 

FUZZER_SEED_ADDITIONS_TOPIC = "fuzzer_seed_additions"
FUZZER_SEED_REQUESTS_TOPIC = "fuzzer_seed_requests"
FUZZER_SEED_UPDATES_TOPIC = "fuzzer_seed_updates"

FUZZER_COVERAGE_REQUESTS_TOPIC = "fuzzer_coverage_requests"
FUZZER_COVERAGE_RESPONSES_TOPIC = "fuzzer_coverage_responses"

CUSTOM_FUZZER_RUN_REQUEST_TOPIC = "custom_fuzzer_run_request"
CUSTOM_FUZZER_RUN_RESPONSE_TOPIC = "custom_fuzzer_run_response"
CUSTOM_FUZZER_STOP_REQUEST_TOPIC = "custom_fuzzer_stop_request"
CUSTOM_FUZZER_STOP_RESPONSE_TOPIC = "custom_fuzzer_stop_response"

DIRECTED_FUZZER_REQUEST_TOPIC   = "directed_fuzzer_request"
DIRECTED_FUZZER_RESPONSE_TOPIC      = "directed_fuzzer_response"

C_LLM_RESULTS_TOPIC = "c_llm_corpus"
CORPUS_PATH_TOPIC = "corpus_path_topic"
DEEP_BROWSER_REQUEST_TOPIC = "deep_browser_request"
SARIF_HARNESS_REACHABILITY_TOPIC = "sarif_harness_reachability"
SARIF_DIRECTED_TOPIC = "sarif_directed"
DELTA_DIRECTED_TOPIC = "delta_directed"

ALL_TOPICS = [
    CP_CONFIG_TOPIC,
    HELLO_TOPIC,
    FILE_OPS_TOPIC,
    FILE_OPS_RESPONSE_TOPIC,
    OSV_ANALYZER_RESULTS_TOPIC,
    HARNESS_BUILDER_REQUEST_TOPIC,
    HARNESS_BUILDER_RESULT_TOPIC,
    FUZZER_RUN_REQUEST_TOPIC,
    FUZZER_RUN_RESPONSE_TOPIC,
    FUZZER_STOP_REQUEST_TOPIC,
    FUZZER_STOP_RESPONSE_TOPIC,
    FUZZER_LAUNCH_ANNOUNCEMENT_TOPIC,
    HARNESS_PRIORITIZATION_TOPIC,
    LLM_MUTATOR_REQUEST_TOPIC,
    LLM_MUTATOR_RESPONSE_TOPIC,
    FUZZER_SEED_SUGGESTIONS_TOPIC,
    CRASHING_SEED_SUGGESTIONS_TOPIC,
    DEEPGEN_REQUEST_TOPIC,
    DEEPGEN_RESPONSE_TOPIC,
    FUZZER_SEED_ADDITIONS_TOPIC,
    FUZZER_SEED_REQUESTS_TOPIC,
    FUZZER_SEED_UPDATES_TOPIC,
    FUZZER_COVERAGE_REQUESTS_TOPIC,
    FUZZER_COVERAGE_RESPONSES_TOPIC,
    CUSTOM_FUZZER_RUN_REQUEST_TOPIC,
    CUSTOM_FUZZER_RUN_RESPONSE_TOPIC,
    CUSTOM_FUZZER_STOP_REQUEST_TOPIC,
    CUSTOM_FUZZER_STOP_RESPONSE_TOPIC,
    DIRECTED_FUZZER_REQUEST_TOPIC,
    DIRECTED_FUZZER_RESPONSE_TOPIC,
    C_LLM_RESULTS_TOPIC,
    CORPUS_PATH_TOPIC,
    DEEP_BROWSER_REQUEST_TOPIC,
    SARIF_HARNESS_REACHABILITY_TOPIC,
    SARIF_DIRECTED_TOPIC,
    DELTA_DIRECTED_TOPIC,
]
