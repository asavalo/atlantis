import os

NODE_IDX = int(os.environ.get("NODE_IDX", 0))
GROUP_ID = "c_llm" + "_" + str(NODE_IDX)

NUM_LLM_MUTATOR_THREADS = 1
NUM_FUZZER_STOP_RESPONSE_THREADS = 1
