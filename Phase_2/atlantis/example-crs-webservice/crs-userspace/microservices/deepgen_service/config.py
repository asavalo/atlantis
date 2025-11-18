import os

NODE_IDX = int(os.environ.get("NODE_IDX", 0))
GROUP_ID = "deepgen_service" + "_" + str(NODE_IDX)

NUM_DEEPGEN_SERVICE_THREADS = 1
NUM_FUZZER_MANAGER_RUN_THREADS = 1
NUM_FUZZER_MANAGER_STOP_THREADS = 1
NUM_FUZZER_MANAGER_LAUNCH_THREADS = 1
NUM_HARNESS_PRIORITIZATION_THREADS = 1

GIT_USER_NAME = "DeepGen"
GIT_USER_EMAIL = "deepgen@example.com"


TASK_QUEUE_ADDR = "ipc:///tmp/ipc/task_queue"
ACK_QUEUE_ADDR = "ipc:///tmp/ipc/ack_queue"
REQREP_ADDR = "ipc:///tmp/ipc/reqrep_queue"


general_models = {
    "o3": 35,
    "o4-mini": 10,
    "gemini-2.5-pro": 40,
    "claude-opus-4-20250514": 15,
}

evolve_models = {
    "o3": 30,
    "gemini-2.5-pro": 30,
    "claude-opus-4-20250514": 40,
}

script_fixing_models = {
    "gemini-2.5-pro": 40,
    "o4-mini": 40,
    "o3": 40,
}