from abc import ABC, abstractmethod
from uuid import UUID
from typing import Optional
from .redis_util import BundleInfo, RedisUtil
from vapi_server.models.types import (
    Assessment,
    POVSubmission,
    PatchSubmissionResponse,
    POVSubmissionResponse,
    SubmissionStatus,
    PatchSubmission,
    SarifAssessmentSubmission,
    Sarif,
)
from .api_util import (
    capi_update_bundle,
    capi_submit_bundle,
    capi_delete_bundle,
    send_pov_sarif_match_request,
)
import sarif_client
import time

TEST_MAP = {}


class BundleAlgo:
    def __init__(self, log_info, redis_util, is_test=False):
        self.info = log_info
        self.redis_util = redis_util
        self.pov_id_repr_map = {}

        self.is_test = is_test

    def __check_pov_sarif_matched(self, pov_id: UUID, sarif_id: UUID) -> bool:
        if self.is_test:
            ret = False
            if pov_id in TEST_MAP:
                ret = TEST_MAP[pov_id] == sarif_id
            self.info(
                f"[TEST] Matched result: {ret}, pov_id: {pov_id}, sarif_id: {sarif_id}"
            )
            return ret
        else:
            sarif_key = self.redis_util.to_sarif_key(sarif_id)
            sarif = self.redis_util.get_sarif(sarif_key)
            if sarif is None:
                return False
            pov_subission = self.redis_util.get_pov_submission(pov_id)
            if pov_subission is None:
                return False
            raw_crash_log = self.redis_util.get_raw_crashlog(pov_id)
            if raw_crash_log is None:
                return False
            sarif_match_request = sarif_client.SARIFMatchRequest(
                metadata=sarif.metadata, sarif=sarif.sarif, sarif_id=str(sarif.sarif_id)
            )
            pov_match_request = sarif_client.POVMatchRequest(
                pov_id=str(pov_id),
                fuzzer_name=pov_subission.fuzzer_name,
                sanitizer=pov_subission.sanitizer,
                testcase=pov_subission.testcase,
                crash_log=raw_crash_log,
            )
            while True:
                res = send_pov_sarif_match_request(
                    pov_match_request, sarif_match_request
                )
                if res is None:
                    return False
                self.info(
                    f"Check POV SARIF matching.. pov_id: {pov_id}, sarif: {sarif_id}, res: {res}"
                )
                if sarif_client.PoVSarifMatchResponse.PENDING.value == res.value:
                    self.info("Pending, sleep 5 seconds")
                    time.sleep(5)
                elif sarif_client.PoVSarifMatchResponse.MATCHED.value == res.value:
                    return True
                else:
                    return False
        return False

    def __capi_submit_bundle_test(self, bundle: BundleInfo) -> UUID:
        self.info(f"[TEST] CAPI submit bundle: {bundle}")
        if bundle.bundle_id is None:
            ret = self.redis_util.create_uuid("bundle")
            self.info(f"[TEST][CAPI] Create bundle: {ret} => {bundle}")
            return ret
        else:
            self.info(f"[TEST][CAPI] Update bundle: {bundle.bundle_id} => {bundle}")
            return bundle.bundle_id

    def __capi_submit_bundle(self, bundle: BundleInfo) -> UUID:
        if self.is_test:
            return self.__capi_submit_bundle_test(bundle)
        else:
            bundle_id = bundle.bundle_id
            capi_pov_id = bundle.capi_pov_id
            capi_patch_id = bundle.capi_patch_id
            broadcast_sarif_id = bundle.broadcast_sarif_id
            if bundle_id is None:
                res = capi_submit_bundle(capi_pov_id, capi_patch_id, broadcast_sarif_id)
                self.info(
                    f"[CAPI] Submit Bundle pov_id: {capi_pov_id} patch_id: {capi_patch_id} sarif_id: {broadcast_sarif_id}"
                    + f" => bundle_id: {res.bundle_id} status: {res.status.value}"
                )
                return UUID(res.bundle_id)
            else:
                res = capi_update_bundle(
                    bundle_id, capi_pov_id, capi_patch_id, broadcast_sarif_id
                )
                self.info(
                    f"[CAPI] Update Bundle bundle_id: {bundle_id} pov_id: {capi_pov_id} patch_id: {capi_patch_id} sarif_id: {broadcast_sarif_id}"
                    + f" => bundle_id: {res.bundle_id} status: {res.status.value}"
                )
                return UUID(res.bundle_id)

    def __capi_delete_bundle(self, bundle: BundleInfo):
        if self.is_test:
            self.info(f"[TEST][CAPI] Delete bundle: {bundle}")
            return
        else:
            if bundle.bundle_id is None:
                return
            res = capi_delete_bundle(bundle.bundle_id)
            self.info(f"[CAPI] Delete Bundle bundle_id: {bundle.bundle_id} => {res}")

    def __get_patch_submission(self, patch_id: UUID):
        return self.redis_util.get_patch_submission(patch_id)

    def __get_pov_repr(self, pov_id: UUID) -> UUID:
        return self.redis_util.get_pov_repr(pov_id)

    def __get_pov_ids_with_repr(self, pov_repr: UUID) -> list[UUID]:
        if pov_repr in self.pov_id_repr_map:
            return self.pov_id_repr_map[pov_repr]
        ret = self.redis_util.get_pov_ids_with_repr(pov_repr)
        self.pov_id_repr_map[pov_repr] = ret
        return ret

    def __get_bundle_lock(self):
        return self.redis_util.get_bundle_algo_lock()

    def __list_bundles(self) -> list[BundleInfo]:
        return self.redis_util.list_bundles()

    def __get_bundle_by_pov_id(self, pov_id: UUID) -> BundleInfo | None:
        return self.redis_util.get_bundle_by_pov_id(pov_id)

    def __try_write_pov_sarif_map(self, pov_id: UUID, sarif_id: UUID) -> bool:
        return self.redis_util.write_pov_sarif_map(pov_id, sarif_id)

    def __read_pov_sarif_map(self, pov_id: UUID) -> UUID | None:
        return self.redis_util.read_pov_sarif_map(pov_id)

    def __write_bundle_db(self, bundle: BundleInfo):
        self.redis_util.write_bundle(bundle)

    def __has_similar_bundle(self, new_bundle: BundleInfo) -> bool:
        # under get_bundle_lock
        for bundle in self.__list_bundles():
            if bundle.bundle_id is None:
                continue
            if (
                bundle.bundle_id is not None
                and bundle.bundle_id == new_bundle.bundle_id
            ):
                continue
            if bundle.capi_pov_id == new_bundle.capi_pov_id:
                return True
            if (
                bundle.capi_patch_id is not None
                and bundle.capi_patch_id == new_bundle.capi_patch_id
            ):
                return True
            if (
                bundle.broadcast_sarif_id is not None
                and bundle.broadcast_sarif_id == new_bundle.broadcast_sarif_id
            ):
                return True
        return False

    def __try_submit_bundle(self, new_bundle: BundleInfo) -> Optional[BundleInfo]:
        # under get_bundle_lock
        if self.__has_similar_bundle(new_bundle):
            return None
        new_bundle.bundle_id = self.__capi_submit_bundle(new_bundle)
        if new_bundle.bundle_id is None:
            return None
        self.__write_bundle_db(new_bundle)
        return new_bundle

    def __delete_bundle(self, bundle: BundleInfo):
        # under get_bundle_lock
        if bundle.bundle_id is None:
            return
        self.__capi_delete_bundle(bundle)
        bundle.bundle_id = None
        self.__write_bundle_db(bundle)

    def __try_submit_pov_sarif_bundle(
        self, pov_id: UUID, sarif_id: UUID
    ) -> Optional[BundleInfo]:
        # under get_bundle_lock
        capi_pov_id = self.redis_util.get_capi_pov_id(pov_id)
        if capi_pov_id is None:
            return
        bundle = BundleInfo(
            capi_pov_id=capi_pov_id, pov_id=pov_id, broadcast_sarif_id=sarif_id
        )
        return self.__try_submit_bundle(bundle)

    def __try_submit_pov_patch_bundle(
        self, pov_id: UUID, patch_id: UUID, sarif_id: Optional[UUID] = None
    ) -> Optional[BundleInfo]:
        # under get_bundle_lock
        capi_pov_id = self.redis_util.get_capi_pov_id(pov_id)
        if capi_pov_id is None:
            return
        capi_patch_id = self.redis_util.get_capi_patch_id(patch_id)
        if capi_patch_id is None:
            return
        bundle = BundleInfo(
            capi_pov_id=capi_pov_id,
            capi_patch_id=capi_patch_id,
            pov_id=pov_id,
            patch_id=patch_id,
            broadcast_sarif_id=sarif_id,
        )
        return self.__try_submit_bundle(bundle)

    def __is_pov_sarif_matched(self, pov_id: UUID, sarif_id: UUID) -> bool:
        # Outside of get_bundle_lock
        self.info(
            f"is_pov_sarif_matched: {pov_id}, {sarif_id}, {self.__get_pov_repr(pov_id)}"
        )
        for pov in self.__get_pov_ids_with_repr(self.__get_pov_repr(pov_id)):
            if self.__read_pov_sarif_map(pov) == sarif_id:
                return True
        if self.__check_pov_sarif_matched(pov_id, sarif_id):
            return self.__try_write_pov_sarif_map(pov_id, sarif_id)
        return False

    def __add_all_povs_to_sarif(self, pov_id: UUID, sarif_id: UUID):
        with self.__get_bundle_lock():
            pov_repr = self.__get_pov_repr(pov_id)
            for pov in self.__get_pov_ids_with_repr(pov_repr):
                if not self.__try_write_pov_sarif_map(pov, sarif_id):
                    return False
            return True

    def __bundle_pov_sarif_with_existing_bundle(
        self, pov_id: UUID, sarif_id: UUID
    ) -> bool:
        """
        ended: bool
        """
        if not self.__is_pov_sarif_matched(pov_id, sarif_id):
            self.info(f"Pov {pov_id} and sarif {sarif_id} are not matched")
            return False
        self.info(f"Pov {pov_id} and sarif {sarif_id} are matched")
        with self.__get_bundle_lock():
            bundle = self.__get_bundle_by_pov_id(pov_id)
            if bundle is not None:
                if bundle.broadcast_sarif_id is None:
                    bundle.broadcast_sarif_id = sarif_id
                    submitted_bundle = self.__try_submit_bundle(bundle)
                    if submitted_bundle is None:
                        return False
                    return submitted_bundle.broadcast_sarif_id == sarif_id
                else:
                    return bundle.broadcast_sarif_id != sarif_id
        return False

    def bundle_pov_sarif(self, pov_id: UUID, sarif_id: UUID):
        self.info(f"Start bundle_pov_sarif: {pov_id}, {sarif_id}")
        if not self.__add_all_povs_to_sarif(pov_id, sarif_id):
            return
        pov_repr = self.__get_pov_repr(pov_id)
        if self.__bundle_pov_sarif_with_existing_bundle(pov_repr, sarif_id):
            return
        for bundle in self.__list_bundles():
            if bundle.bundle_id is None:
                continue
            if bundle.broadcast_sarif_id is not None:
                continue
            if self.__bundle_pov_sarif_with_existing_bundle(bundle.pov_id, sarif_id):
                return
        with self.__get_bundle_lock():
            ret = self.__try_submit_pov_sarif_bundle(pov_repr, sarif_id)
            if ret is None:
                self.info(
                    f"Skip create a new bundle with pov_id: {pov_id}, sarif_id: {sarif_id}"
                )
            else:
                self.info(
                    f"Create a new bundle with pov_id: {pov_id}, sarif_id: {sarif_id}"
                )

    def __propagate_pov_repr(
        self, pov_repr: UUID, patched_again_pov_ids: list[UUID]
    ) -> list[UUID]:
        pov_group = [pov_repr] + patched_again_pov_ids
        for pov in pov_group:
            self.redis_util.set_pov_repr(pov, pov_repr)
        return pov_group

    def bundle_pov_patch(self, pov_id: UUID, patch_id: UUID):
        self.info(f"Start bundle_pov_patch: {pov_id}, {patch_id}")
        patch_submission = self.__get_patch_submission(patch_id)
        sarif_cands = set()
        bundle = None
        with self.__get_bundle_lock():
            pov_ids = self.__propagate_pov_repr(
                pov_id, patch_submission.patched_again_pov_ids
            )
            for p in pov_ids:
                bundle = self.__get_bundle_by_pov_id(p)
                if bundle is not None:
                    self.__delete_bundle(bundle)
                    sarif_id = bundle.broadcast_sarif_id
                    if sarif_id is not None:
                        sarif_cands.add(sarif_id)
            bundle = self.__try_bundle_pov_patch_with_sarif(
                pov_id, patch_id, sarif_cands
            )
            if bundle is None:
                return
        sarif_cands = self.__get_sarif_cands(pov_id)
        if len(sarif_cands) == 1:
            sarif_id = list(sarif_cands)[0]
            with self.__get_bundle_lock():
                for to_delete_bundle in self.__list_bundles():
                    if to_delete_bundle.bundle_id is None:
                        continue
                    if to_delete_bundle.broadcast_sarif_id == sarif_id:
                        self.__delete_bundle(to_delete_bundle)
                bundle.broadcast_sarif_id = sarif_id
                self.__try_submit_bundle(bundle)
                return

    def __try_bundle_pov_patch_with_sarif(
        self, pov_id: UUID, patch_id: UUID, sarif_cands: set[UUID]
    ) -> Optional[BundleInfo]:
        # under get_bundle_lock
        if len(sarif_cands) == 1:
            sarif = list(sarif_cands)[0]
            bundle = self.__try_submit_pov_patch_bundle(pov_id, patch_id, sarif)
        else:
            bundle = self.__try_submit_pov_patch_bundle(pov_id, patch_id)
        if bundle is None:
            self.info(
                f"Skip create a new bundle with pov_id: {pov_id}, patch_id: {patch_id}"
            )
            return
        if len(sarif_cands) != 0:
            return
        return bundle

    def __bundle_has_all_matched_sarif(
        self, bundles: list[BundleInfo], sarif_id: UUID
    ) -> bool:
        for bundle in bundles:
            if (
                bundle.broadcast_sarif_id == sarif_id
                and bundle.capi_patch_id is not None
                and bundle.capi_pov_id is not None
                and bundle.bundle_id is not None
            ):
                return True
        return False

    def __get_sarif_cands(self, pov_id: UUID) -> set[UUID]:
        sarif_cands = set()
        unfinished_sarifs = []
        with self.__get_bundle_lock():
            bundles = self.__list_bundles()
            for sarif in self.redis_util.list_sarif_submits():
                if sarif.assessment.value != Assessment.AssessmentCorrect.value:
                    continue
                if self.__bundle_has_all_matched_sarif(bundles, sarif.sarif_id):
                    continue
                unfinished_sarifs.append(sarif)
        self.info(f"unfinished_sarif_ids: {unfinished_sarifs}")

        for sarif in unfinished_sarifs:
            if sarif.pov_id == pov_id:
                sarif_cands.add(sarif.sarif_id)
            else:
                sarif_id = sarif.sarif_id
                if self.__is_pov_sarif_matched(pov_id, sarif_id):
                    sarif_cands.add(sarif_id)
        return sarif_cands


def test_add_pov(redis_util, pov_id):
    capi_pov_id = pov_id
    key = redis_util.to_pov_capi_key(str(pov_id))
    redis_util.write(
        key,
        POVSubmissionResponse(
            pov_id=capi_pov_id, status=SubmissionStatus.SubmissionStatusAccepted
        ).model_dump_json(),
    )
    redis_util.set_pov_repr(pov_id, pov_id)
    redis_util.set_pov_time(pov_id)
    print(f"[CAPI] Submit POV: pov_id: {pov_id}")


def test_add_patch(redis_util, pov_id, patch_id, patched_again_pov_ids=[]):
    patch_task_key = redis_util.to_patch_key(patch_id)
    body = PatchSubmission(
        patched_again_pov_ids=list(map(str, patched_again_pov_ids)), patch=""
    )
    redis_util.write(patch_task_key, body.model_dump_json())
    patch_result_key = redis_util.to_patch_capi_key(patch_id)
    redis_util.write(
        patch_result_key,
        PatchSubmissionResponse(
            patch_id=patch_id, status=SubmissionStatus.SubmissionStatusAccepted
        ).model_dump_json(),
    )
    pov_of_patch = redis_util.to_pov_of_patch_key(patch_id)
    redis_util.write(pov_of_patch, str(pov_id))
    print(f"[CAPI] Submit Patch: pov_id: {pov_id}, patch_id: {patch_id}")
    BundleAlgo(print, redis_util, is_test=True).bundle_pov_patch(pov_id, patch_id)


def test_add_sarif(redis_util, pov_id, sarif_id):
    body = SarifAssessmentSubmission(
        sarif_id=sarif_id,
        pov_id=pov_id,
        assessment=Assessment.AssessmentCorrect,
        description="",
    )
    redis_util.add_sarif_submission(body.sarif_id, body)
    BundleAlgo(print, redis_util, is_test=True).bundle_pov_sarif(pov_id, sarif_id)


def bundle_to_str(bundle: BundleInfo):
    if bundle.bundle_id is None:
        ret = "- BundleInfo [DELETED]\n"
    else:
        ret = "- BundleInfo\n"
    ret += f"           bundle_id: {bundle.bundle_id}\n"
    ret += f"              pov_id: {bundle.pov_id}\n"
    ret += f"            patch_id: {bundle.patch_id}\n"
    ret += f"         capi_pov_id: {bundle.capi_pov_id}\n"
    ret += f"       capi_patch_id: {bundle.capi_patch_id}\n"
    ret += f"  broadcast_sarif_id: {bundle.broadcast_sarif_id}"
    return ret


def check_status(redis_util):
    for bundle in redis_util.list_bundles():
        print("=" * 80)
        print(bundle_to_str(bundle))
    print("=" * 80)


if __name__ == "__main__":
    redis_util = RedisUtil()
    pov_id1 = UUID("00000000-0000-0000-0000-000000000001")
    pov_id2 = UUID("00000000-0000-0000-0000-000000000002")
    pov_id3 = UUID("00000000-0000-0000-0000-000000000003")

    patch_id1 = UUID("11111111-0000-0000-0000-000000000001")
    patch_id2 = UUID("11111111-0000-0000-0000-000000000002")
    patch_id3 = UUID("11111111-0000-0000-0000-000000000003")

    sarif_id1 = UUID("22222222-0000-0000-0000-000000000001")
    # TEST_MAP = {
    #     pov_id2: sarif_id1,
    # }

    test_add_pov(redis_util, pov_id1)
    test_add_pov(redis_util, pov_id2)
    test_add_pov(redis_util, pov_id3)

    print("=" * 80)
    test_add_sarif(redis_util, pov_id1, sarif_id1)
    print("=" * 80)
    test_add_patch(redis_util, pov_id1, patch_id1)
    test_add_patch(redis_util, pov_id2, patch_id2, [pov_id1])
    test_add_patch(redis_util, pov_id3, patch_id3, [pov_id1, pov_id2])
    check_status(redis_util)
    # check_status(redis_util)
    # test_add_patch(redis_util, pov_id1, patch_id2, [pov_id2])
    # check_status(redis_util)
