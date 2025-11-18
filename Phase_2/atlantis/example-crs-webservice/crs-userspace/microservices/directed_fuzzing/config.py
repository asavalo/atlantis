from libatlantis.constants import IN_K8S, CRS_SCRATCH_DIR, ARTIFACTS_DIR, LARGE_DATA_DIR, SHARED_CRS_DIR
import os

CRS_DOCKER_MOUNTS = os.environ.get("CRS_DOCKER_MOUNTS", "")
NODE_IDX = int(os.environ.get("NODE_IDX", 0))
GROUP_ID = "directed_fuzzer" + "_" + str(NODE_IDX)
NUM_DIRECTED_FUZZER_THREADS = 1

BROKER_PORT = 13337
CENTRALIZED_BROKER_PORT = 13338

FUZZ_OUT_LOG_FILE = "task-fuzz-out.log"
FUZZ_ERR_LOG_FILE = "task-fuzz-err.log"

COMPILE_OUT_LOG_FILE = "task-compile-out.log"
COMPILE_ERR_LOG_FILE = "task-compile-err.log"

# 1 hour compilation
COMPILE_TIMEOUT = 60 * 60 * 1

# Bullseye config:
BULLSEYE_CONTEXT_MAX_DEPTH = 1
BULLSEYE_FUZZER_FLAGS = "-m none -t 10000+"
