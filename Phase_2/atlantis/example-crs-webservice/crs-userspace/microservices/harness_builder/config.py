import os
from libatlantis.constants import CRS_SCRATCH_DIR, SHARED_CRS_DIR

NODE_IDX = int(os.environ.get("NODE_IDX", 0))
GROUP_ID = "harness_builder" + "_" + str(NODE_IDX)

NUM_HARNESS_BUILDER_BUILD_THREADS = 2

# If running in Docker, and using the host Docker for helper.py,
# this MUST be in an externally mounted volume and not local to this
# container
STORAGE_DIR = CRS_SCRATCH_DIR / "harness-builder-build"
HARNESS_SHARE_DIR = SHARED_CRS_DIR / "crs-userspace/harness-builder-build"
