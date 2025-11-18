import os
import sys
import time
import base64
import threading
from uuid import UUID, uuid4
from pathlib import Path
import re
import hashlib
import multiprocessing
import json

from vapi_server.models.types import (
    POVSubmissionResponse,
    SubmissionStatus,
)
from crs_webserver.my_crs.task_server.models.types import TaskType
from typing import Tuple, Optional
from .redis_util import RedisUtil
from .cp import CP
from .api_util import (
    capi_submit_pov,
    capi_check_pov_result,
    send_patch_request,
    send_pov_match_request,
)
from .pov_dedup import CrashLog, dedup_crash_log
from libCRS import install_otel_logger

install_otel_logger()

from loguru import logger
from crs_webserver.my_crs.crs_manager.log_config import setup_logger

setup_logger()
SLEEP = 10
VERIFIER_HEAD_WORKDIR = Path(os.getenv("VERIFIER_HEAD_WORKDIR"))
VERIFIER_BASE_WORKDIR = Path(os.getenv("VERIFIER_BASE_WORKDIR"))
CRASH_RET_CODES = [
    1,  # LibFuzzer Sanitizer crash
    70,  # LibFuzzer Timeout
    71,  # LibFuzzer OOM
    77,  # LibFuzzer Default (OOM, leak, etc) and/or Jazzer Sanitizer Crash
]

POV_BLOB_HASH_DIR = Path("/pov_blob_hash")


class POVSubmit:
    def __init__(self, pov_id: str):
        self.pov_id = UUID(pov_id)
        self.task_id = UUID(os.getenv("TASK_ID"))
        self.redis = RedisUtil()
        self.pov_submission = self.redis.get_pov_submission(self.pov_id)
        self.task = self.redis.get_task_detail(self.task_id)
        self.is_delta_mode = self.task.type.value == TaskType.TaskTypeDelta.value

    def info(self, msg):
        logger.info(f"[POVSubmit][{self.pov_id}] {msg}")

    def __is_same_as_previous_pov(self) -> bool:
        try:
            blob = base64.b64decode(self.pov_submission.testcase)
            harness_name = self.pov_submission.fuzzer_name
            sanitizer = self.pov_submission.sanitizer
            hash_key = hashlib.md5(
                blob + harness_name.encode() + sanitizer.encode()
            ).hexdigest()
            os.makedirs(POV_BLOB_HASH_DIR, exist_ok=True)
            hash_path = POV_BLOB_HASH_DIR / hash_key
            if hash_path.exists():
                same_pov_id = hash_path.read_text()
                self.info(f"This has the same blob + harness with {same_pov_id}")
                return True
            hash_path.write_text(str(self.pov_id))
        except Exception as e:
            pass
        return False

    def main(self):
        self.info(f"Main {self.pov_submission}")
        if self.__is_same_as_previous_pov():
            self.info(
                "Skip, This has the same blob under the same harness as previous POV"
            )
            return
        (verified, raw_crash_log, crash_log) = self.verify()
        if not verified:
            self.info("Verify fail!")
            return
        raw_crash_log = base64.b64encode(raw_crash_log).decode("utf-8")
        self.redis.write_raw_crashlog(self.pov_id, raw_crash_log)
        self.redis.set_pov_time(self.pov_id)
        self.redis.set_pov_repr(self.pov_id, self.pov_id)
        capi_pov_id = self.submit_capi()
        self.redis.incr_state("waiting")
        thread = threading.Thread(target=self.invoke_patch, args=(crash_log,))
        thread.start()
        ret = self.check_capi_result(capi_pov_id)
        if ret.value == SubmissionStatus.SubmissionStatusPassed.value:
            self.redis.decr_state("waiting")
            self.redis.incr_state("succeeded")
            self.info("Request SARIF pov matching")
            send_pov_match_request(
                self.pov_id,
                self.pov_submission.fuzzer_name,
                self.pov_submission.sanitizer,
                self.pov_submission.testcase,
                raw_crash_log,
            )
        else:
            self.redis.decr_state("waiting")
            self.redis.incr_state("failed")
        thread.join()

    def is_valid_crash_ret_code(self, ret_code: int):
        return ret_code in CRASH_RET_CODES

    def verify(self) -> Tuple[bool, bytes, Optional[CrashLog]]:
        self.info("Verify..")
        language, ret_code, raw_crash_log = self.run_pov_on_head()
        if not self.is_valid_crash_ret_code(ret_code):
            self.__update_as(SubmissionStatus.SubmissionStatusFailed)
            self.info(f"POV does not crash CP on head, ret_code: {ret_code}")
            return False, raw_crash_log, None
        if self.is_delta_mode:
            base_ret_code = self.run_pov_on_base()[1]
            if self.is_valid_crash_ret_code(base_ret_code):
                self.__update_as(SubmissionStatus.SubmissionStatusFailed)
                self.info(
                    f"POV triggers crash on base => fail!, ret_code: {base_ret_code}"
                )
                return False, raw_crash_log, None
        should_submit, crash_log = self.should_submit_pov(
            raw_crash_log, language == "jvm"
        )
        if not should_submit:
            self.__update_as(SubmissionStatus.SubmissionStatusDuplicated)
            self.info("This is duplicated POV")
            return False, raw_crash_log, None
        self.info("POV is verified!!")
        return True, raw_crash_log, crash_log

    def run_pov_on_head(self) -> (str, int, bytes):
        return self.__run_pov(VERIFIER_HEAD_WORKDIR)

    def run_pov_on_base(self) -> (str, int, bytes):
        return self.__run_pov(VERIFIER_BASE_WORKDIR)

    def __run_pov(self, workdir: Path) -> (str, int, bytes):
        # Return return code, crash_log
        sanitizer = self.pov_submission.sanitizer
        harness_name = self.pov_submission.fuzzer_name
        self.info(f"Run POV under {harness_name} {sanitizer} at {workdir}")
        pov_path = self.__save_pov(workdir)
        cp = CP(self.task.project_name, workdir / sanitizer)
        ret_code, crash_log = cp.reproduce(harness_name, pov_path)
        self.info(f"ret_code: {ret_code}, crash_log: {crash_log}")
        return cp.get_language(), ret_code, crash_log

    def __save_pov(self, workdir: Path) -> Path:
        pov_dir = workdir / "pov"
        os.makedirs(str(pov_dir), exist_ok=True)
        pov_path = pov_dir / str(self.pov_id)
        testcase = base64.b64decode(self.pov_submission.testcase)
        self.info(f"Save POV into {pov_path}")
        pov_path.write_bytes(testcase)
        return pov_path

    def should_submit_pov(
        self, raw_crash_log: bytes, is_jvm: bool
    ) -> Tuple[bool, CrashLog]:
        self.info("Check uniqueness")
        with self.redis.get_pov_dedup_lock(self.task_id):
            pov_groups = self.redis.get_pov_groups(self.task_id)
            (should_submit, is_unique, group_id, crash_log) = dedup_crash_log(
                pov_groups, raw_crash_log, is_jvm
            )
            self.redis.set_pov_crashlog(self.pov_id, crash_log)
            self.info(
                f"should_submit: {should_submit}, is_unique: {is_unique}, group_id: {group_id}, crash_log: {crash_log}"
            )
            if is_unique:
                self.redis.add_pov_group(self.task_id, group_id, self.pov_id)
            return should_submit, crash_log

    def submit_capi(self):
        self.info("Submit CAPI")
        ret = self.__do_submit_capi()
        self.__update_capi_result(ret)
        return ret.pov_id

    def __update_capi_result(self, ret: POVSubmissionResponse):
        key = self.redis.to_pov_capi_key(str(self.pov_id))
        self.redis.write(key, ret.model_dump_json())

    def __update_as(self, status: SubmissionStatus):
        res = POVSubmissionResponse(pov_id=self.pov_id, status=status)
        self.__update_capi_result(res)

    def __do_submit_capi(self):
        self.info(f"Submit POV to CAPI")
        res = capi_submit_pov(
            self.pov_submission.fuzzer_name,
            self.pov_submission.sanitizer,
            self.pov_submission.testcase,
        )
        if res == None:
            self.info("Error in submitting POV to CAPI")
            return
        self.info(f"[CAPI] Submit pov_id: {res.pov_id}, status: {res.status.value}")
        return POVSubmissionResponse.model_validate(res.to_dict())

    def check_capi_result(self, capi_pov_id):
        self.info("Check CAPI Result")
        while True:
            ret = self.__do_check_capi_result(capi_pov_id)
            if (
                ret != None
                and ret.status.value != SubmissionStatus.SubmissionStatusAccepted.value
            ):
                self.__update_capi_result(ret)
                return ret.status
            time.sleep(SLEEP)

    def __do_check_capi_result(self, capi_pov_id):
        res = capi_check_pov_result(capi_pov_id)
        if res == None:
            return None
        self.info(
            f"[CAPI] Check Result pov_id: {res.pov_id}, status: {res.status.value}"
        )
        return POVSubmissionResponse.model_validate(res.to_dict())

    def should_invoke_patch(self, crash_log: CrashLog) -> bool:
        task_id = self.task_id
        fuzzer_name = self.pov_submission.fuzzer_name
        sanitizer = str(crash_log.sanitizer)
        with self.redis.patch_requested_sanitizers_lock(task_id, fuzzer_name):
            sanitizers = self.redis.get_patch_requested_sanitizers(task_id, fuzzer_name)
            self.info(
                f"should_invoke_patch: fuzzer_name: {fuzzer_name}, sanitizer: {sanitizer}"
            )
            cnt = 0
            if sanitizer in sanitizers:
                cnt = sanitizers[sanitizer]
            self.info(f"already_requested_sanitizers: {cnt}, {sanitizers}")
            if cnt >= 10:
                self.info(
                    "Skip patch request because patch request/fuzzer+sanitizer is limited to 10"
                )
                return False
            sanitizers[sanitizer] = cnt + 1
            self.redis.set_patch_requested_sanitizers(task_id, fuzzer_name, sanitizers)
            return True

    def invoke_patch(self, crash_log: CrashLog):
        if not self.should_invoke_patch(crash_log):
            return
        self.info("Invoke Patch")
        res = send_patch_request(
            self.task.project_name,
            self.pov_submission.fuzzer_name,
            self.pov_submission.sanitizer,
            self.pov_submission.testcase,
            self.pov_id,
            self.task.type.value,
        )
        self.info("Patch request is sent!")


if __name__ == "__main__":
    POVSubmit(sys.argv[1]).main()
