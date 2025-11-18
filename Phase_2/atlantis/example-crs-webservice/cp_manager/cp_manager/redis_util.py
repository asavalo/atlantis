import os
import time
import redis
import json
import logging
import redis_lock
from uuid import UUID, uuid4
from vapi_server.models.types import (
    POVSubmission,
    PatchSubmissionResponse,
    POVSubmissionResponse,
    PatchSubmission,
    SarifAssessmentSubmission,
    Sarif,
)
from crs_webserver.my_crs.task_server.models.types import TaskDetail
from crs_webserver.my_crs.crs_manager.crs_types import TaskStatus
from .api_util import (
    capi_update_bundle,
)
from .pov_dedup import CrashLog
from pydantic import BaseModel, Field

DUMMY_UUID = UUID("00000000-0000-0000-0000-000000000000")
TASK_ID = os.getenv("TASK_ID", str(DUMMY_UUID))
logging.getLogger("redis_lock").setLevel(logging.WARNING)


class BundleInfo(BaseModel):
    capi_pov_id: UUID
    pov_id: UUID
    bundle_id: UUID | None = None
    patch_id: UUID | None = None
    capi_patch_id: UUID | None = None
    broadcast_sarif_id: UUID | None = None


def connect_redis():
    url = os.getenv("CRS_REDIS_ENDPOINT")
    if url == None:
        os.system(
            f"redis-server --port 22222 --bind localhost --daemonize yes > /dev/null"
        )
        url = "redis://localhost:22222"
        os.environ["CRS_REDIS_ENDPOINT"] = url
    redis_client = redis.from_url(url, decode_responses=True)
    return redis_client


class RedisUtil:
    def __init__(self):
        self.client = connect_redis()

    def read(self, key):
        return self.client.get(key)

    def write(self, key, value):
        return self.client.set(key, value)

    def get_lock(self, name):
        return redis_lock.Lock(self.client, name=name, expire=10, auto_renewal=True)

    def is_launched_before(self):
        key = f"launched-{TASK_ID}"
        if self.read(key) is None:
            self.write(key, "True")
            return False
        return True

    def to_task_key(self, postfix, id):
        return f"{postfix}-{TASK_ID}-{id}"

    def to_pov_key(self, id):
        return self.to_task_key("pov", id)

    def to_pov_time_key(self, id):
        return self.to_task_key("pov-time", id)

    def to_pov_repr_key(self, id):
        return self.to_task_key("pov-repr", id)

    def list_pov(self):
        PREFIX = f"pov-repr-{TASK_ID}-"
        keys = self.client.keys(f"{PREFIX}*")
        ret = []
        for key in keys:
            try:
                ret.append(UUID(key.split(PREFIX)[1]))
            except:
                pass
        return ret

    def to_sarif_key(self, id):
        return self.to_task_key("sarif", id)

    def to_sarif_submit_key(self, id):
        return self.to_task_key("sarif-submit", id)

    def list_sarif_submits(self) -> list[SarifAssessmentSubmission]:
        PREFIX = f"sarif-submit-{TASK_ID}-"
        keys = self.client.keys(f"{PREFIX}*")
        ret = []
        for key in keys:
            raw = self.read(key)
            ret.append(SarifAssessmentSubmission.model_validate_json(raw))
        return ret

    def to_sarif_broadcast_key(self, id):
        return self.to_task_key("sarif-broadcast", id)

    def create_pov_uuid(self):
        return self.create_uuid("pov")

    def to_patch_key(self, id):
        return self.to_task_key("patch", id)

    def to_pov_of_patch_key(self, patch_id):
        return self.to_patch_key(patch_id) + "-pov"

    def create_patch_uuid(self):
        return self.create_uuid("pov")

    def to_pov_capi_key(self, id):
        return self.to_task_key("pov-capi", id)

    def to_patch_capi_key(self, id):
        return self.to_task_key("patch-capi", id)

    def get_pov_time(self, pov_id) -> int:
        key = self.to_pov_time_key(str(pov_id))
        raw = self.read(key)
        try:
            return int(raw)
        except:
            return 0

    def set_pov_time(self, pov_id: UUID):
        pov_time = int(time.time())
        key = self.to_pov_time_key(str(pov_id))
        self.write(key, str(pov_time))

    def set_pov_repr(self, pov_id: UUID, repr_id: UUID):
        key = self.to_pov_repr_key(str(pov_id))
        self.write(key, str(repr_id))

    def get_pov_repr(self, pov_id: UUID) -> UUID:
        key = self.to_pov_repr_key(str(pov_id))
        raw = self.read(key)
        if raw != None:
            return UUID(raw)
        return pov_id

    def get_pov_ids_with_repr(self, pov_repr: UUID) -> list[UUID]:
        ret = []
        for pov in self.list_pov():
            if self.get_pov_repr(pov) == pov_repr:
                ret.append(pov)
        return ret

    def create_uuid(self, postfix):
        while True:
            ret = uuid4()
            key = self.to_task_key(postfix, ret)
            if self.read(key) is None:
                return ret

    def set_llm_key(self, crs_name, key):
        return self.write(f"llm-key-{TASK_ID}-{crs_name}", key)

    def to_pov_crashlog_key(self, pov_id):
        return self.to_task_key("pov-crashlog", f"{pov_id}")

    def get_pov_crashlog_keys(self):
        return self.client.keys(f"pov-crashlog-{TASK_ID}-*")

    def get_pov_submission(self, pov_id: UUID) -> POVSubmission:
        pov_task_key = self.to_pov_key(pov_id)
        raw = self.read(pov_task_key)
        return POVSubmission.model_validate_json(raw)

    def get_task_detail(self, task_id: UUID) -> TaskDetail:
        raw = self.read("task_" + str(task_id))
        return TaskStatus.model_validate_json(raw).detail

    def patch_requested_sanitizers_lock(self, task_id: UUID, fuzzer_name: str):
        return self.get_lock(f"patch-requested-sanitizers-{task_id}-{fuzzer_name}.lock")

    def get_patch_requested_sanitizers_key(
        self, task_id: UUID, fuzzer_name: str
    ) -> str:
        return f"patch-requested-sanitizers-{task_id}-{fuzzer_name}"

    def get_patch_requested_sanitizers(
        self, task_id: UUID, fuzzer_name: str
    ) -> dict[str, int]:
        key = self.get_patch_requested_sanitizers_key(task_id, fuzzer_name)
        raw = self.read(key)
        try:
            if raw != None:
                return json.loads(raw)
        except:
            pass
        return {}

    def set_patch_requested_sanitizers(
        self, task_id: UUID, fuzzer_name: str, sanitizers: dict[str, int]
    ):
        key = self.get_patch_requested_sanitizers_key(task_id, fuzzer_name)
        self.write(key, json.dumps(sanitizers))

    def get_pov_dedup_lock(self, task_id: UUID):
        return self.get_lock(f"pov-unique-{task_id}.lock")

    def to_pov_group_key(self, task_id: UUID, group_id: int):
        return f"pov-group-{task_id}-{group_id}"

    def get_pov_group(self, task_id: UUID, group_id: int) -> list[str]:
        pov_group_key = self.to_pov_group_key(task_id, group_id)
        raw = self.read(pov_group_key)
        if raw is None:
            return []
        try:
            return json.loads(raw)
        except:
            return []

    def get_pov_groups(self, task_id: UUID) -> dict[int, list[CrashLog]]:
        idx = 0
        ret = {}
        while True:
            pov_group = self.get_pov_group(task_id, idx)
            if len(pov_group) == 0:
                break
            ret[idx] = list(map(lambda x: self.get_pov_crashlog(x), pov_group))
            idx += 1
        return ret

    def add_pov_group(self, task_id: UUID, group_id: int, pov_id: UUID):
        pov_group = self.get_pov_group(task_id, group_id)
        pov_group.append(str(pov_id))
        pov_group_key = self.to_pov_group_key(task_id, group_id)
        self.write(pov_group_key, json.dumps(pov_group))

    def get_pov_crashlog(self, pov_id: str) -> CrashLog:
        pov_crashlog_key = self.to_pov_crashlog_key(pov_id)
        raw = self.read(pov_crashlog_key)
        return CrashLog.model_validate_json(raw)

    def set_pov_crashlog(self, pov_id: str, crash_log: CrashLog):
        pov_crashlog_key = self.to_pov_crashlog_key(pov_id)
        self.write(pov_crashlog_key, crash_log.model_dump_json())

    def get_patch_submission(self, patch_id: UUID) -> PatchSubmission:
        patch_task_key = self.to_patch_key(patch_id)
        raw = self.read(patch_task_key)
        return PatchSubmission.model_validate_json(raw)

    def __sarif_submit_lock(self):
        return self.get_lock(f"sarif-submit-{TASK_ID}.lock")

    def get_sarif_submission(self, sarif_id: str) -> SarifAssessmentSubmission:
        key = self.to_sarif_submit_key(sarif_id)
        raw = self.read(key)
        return SarifAssessmentSubmission.model_validate_json(raw)

    def add_sarif_submission(
        self, sarif_id: UUID, sarif_submission: SarifAssessmentSubmission
    ) -> bool:
        key = self.to_sarif_submit_key(sarif_id)
        with self.__sarif_submit_lock():
            if self.read(key) is not None:
                return False
            self.write(key, sarif_submission.model_dump_json())
            return True

    def get_sarif(self, key: str) -> Sarif:
        raw = self.read(key)
        return Sarif.model_validate_json(raw)

    def get_pov_id_of_patch(self, patch_id: UUID) -> UUID:
        key = self.to_pov_of_patch_key(str(patch_id))
        return UUID(self.read(key))

    def get_pov_submission_response(self, pov_id: UUID) -> POVSubmissionResponse | None:
        key = self.to_pov_capi_key(str(pov_id))
        raw = self.read(key)
        if raw != None:
            return POVSubmissionResponse.model_validate_json(raw)

    def get_patch_submission_response(
        self, patch_id: UUID
    ) -> PatchSubmissionResponse | None:
        key = self.to_patch_capi_key(str(patch_id))
        raw = self.read(key)
        if raw != None:
            return PatchSubmissionResponse.model_validate_json(raw)

    def get_capi_pov_id(self, pov_id: UUID) -> UUID:
        response = self.get_pov_submission_response(pov_id)
        if response != None:
            return response.pov_id

    def get_capi_patch_id(self, patch_id: UUID) -> UUID:
        response = self.get_patch_submission_response(patch_id)
        if response != None:
            return response.patch_id

    def incr_state(self, state_key: str):
        self.client.incr(state_key)

    def decr_state(self, state_key: str):
        self.client.decr(state_key)

    def get_bundle_algo_lock(self):
        return self.get_lock(f"bundle-algo-{TASK_ID}.lock")

    def to_bundle_key(self, pov_id: UUID):
        return self.to_task_key("bundle", str(pov_id))

    def write_bundle(self, bundle: BundleInfo):
        key = self.to_bundle_key(bundle.pov_id)
        self.write(key, bundle.model_dump_json())

    def get_bundle_by_pov_id(self, pov_id: UUID) -> BundleInfo | None:
        key = self.to_bundle_key(pov_id)
        raw = self.read(key)
        try:
            if raw != None:
                return BundleInfo.model_validate_json(raw)
        except:
            pass
        return None

    def list_bundles(self) -> list[BundleInfo]:
        PREFIX = f"bundle-{TASK_ID}-"
        keys = self.client.keys(f"{PREFIX}*")
        ret = []
        for key in keys:
            try:
                raw = self.read(key)
                if raw != None:
                    ret.append(BundleInfo.model_validate_json(raw))
            except:
                pass
        return ret

    def to_pov_sarif_map_key(self, pov_id: UUID):
        return self.to_task_key("pov-sarif-map", str(pov_id))

    def get_pov_sarif_map_lock(self):
        return self.get_lock(f"pov-sarif-map-{TASK_ID}.lock")

    def write_pov_sarif_map(self, pov_id: UUID, sarif_id: UUID) -> bool:
        with self.get_pov_sarif_map_lock():
            key = self.to_pov_sarif_map_key(pov_id)
            raw = self.read(key)
            if raw != None and raw != str(sarif_id):
                return False
            self.write(key, str(sarif_id))
            return True

    def read_pov_sarif_map(self, pov_id: UUID) -> UUID | None:
        with self.get_pov_sarif_map_lock():
            key = self.to_pov_sarif_map_key(pov_id)
            raw = self.read(key)
            try:
                if raw != None:
                    return UUID(raw)
            except:
                pass
            return None

    def to_raw_crashlog_key(self, pov_id: UUID):
        return self.to_task_key("raw-crashlog", str(pov_id))

    def get_raw_crashlog(self, pov_id: UUID) -> str | None:
        key = self.to_raw_crashlog_key(pov_id)
        raw = self.read(key)
        if raw != None:
            return raw
        return None

    def write_raw_crashlog(self, pov_id: UUID, raw_crashlog: str):
        key = self.to_raw_crashlog_key(pov_id)
        self.write(key, raw_crashlog)
