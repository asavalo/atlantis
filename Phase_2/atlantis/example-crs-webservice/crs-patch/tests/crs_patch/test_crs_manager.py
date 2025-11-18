from pathlib import Path
from typing import Tuple
from uuid import UUID
import pytest
from crs_patch.services.patch_manager import PatchManager
from crs_patch.models.models import BlobInfo, PatchRequest, TaskType
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection

r2_integration_test_sound_patch_diffs = [
    r"""diff --git a/vuln.c b/vuln.c
index 15206dc..df29443 100644
--- a/vuln.c
+++ b/vuln.c
@@ -26,7 +26,8 @@ bool person_info_parse_file(person_info_t * person_info, const char * const in)
     for (; isspace(in[last_pos]); last_pos++);
 
     // The bug is THE LINE BELOW THIS LINE
-    strcpy(person_info->name, &in[last_pos]);
+    strncpy(person_info->name, &in[last_pos], MAX_STRLEN-1);
+    person_info->name[MAX_STRLEN-1] = '\0';
 
     return true;
-}
\ No newline at end of file
+}
""",
    r"""diff --git a/vuln.c b/vuln.c
index 15206dc..df29443 100644
--- a/vuln.c
+++ b/vuln.c
@@ -26,7 +26,8 @@ bool person_info_parse_file(person_info_t * person_info, const char * const in)
     for (; isspace(in[last_pos]); last_pos++);
 
     // The bug is THE LINE BELOW THIS LINE
-    strcpy(person_info->name, &in[last_pos]);
+    strncpy(person_info->name, &in[last_pos], MAX_STRLEN-1);
+    person_info->name[MAX_STRLEN-1] = '\0'; // Just a comment.
 
     return true;
-}
\ No newline at end of file
+}
""",
]

mock_c_sound_patch_diffs = [
    r"""diff --git a/mock.c b/mock.c
index b7ec61d..fb9e7d1 100644
--- a/mock.c
+++ b/mock.c
@@ -7,7 +7,7 @@
 
 void process_input_header(const uint8_t *data, size_t size) {
   char buf[0x40];
-  if (size > 0 && data[0] == 'A')
+  if (size > 0 && size <= sizeof(buf) && data[0] == 'A')
       memcpy(buf, data, size);
 }

""",
    r"""diff --git a/mock.c b/mock.c
index b7ec61d..4c46741 100644
--- a/mock.c
+++ b/mock.c
@@ -19,7 +19,9 @@ void parse_buffer_section(const uint8_t *data, size_t size) {
   if (buf_size + 8 != size)
     return;
   uint8_t *buf = (uint8_t *)malloc(buf_size);
-  memcpy(&buf[idx], &data[8],  buf_size);
+  if (idx == 0)
+    memcpy(&buf[idx], &data[8], buf_size);
+  free(buf);
 }
 
 #pragma clang optimize on
""",
]


@pytest.mark.integration
def test_add_patch(detection_c_r2_integration_test_cpv_0: Tuple[Path, Path]):
    source_directory, detection_path = detection_c_r2_integration_test_cpv_0
    detection = AIxCCChallengeProjectDetection.from_toml(detection_path)
    patch_manager = PatchManager(
        detection.project_name, detection.mode, source_directory
    )

    patch_request = PatchRequest(
        project_name=detection.project_name,
        blobs=[
            BlobInfo(
                blob_data=blob.blob,
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
            )
            for blob in detection.blobs
        ],
        pov_id=UUID("00000000-0000-0000-0000-000000000000"),
        sarif_report=None,
        type=TaskType.full,
    )

    patch_manager.add_patch(r2_integration_test_sound_patch_diffs[0], patch_request)
    assert patch_manager.patches == {
        r2_integration_test_sound_patch_diffs[0]: patch_request,
    }


@pytest.mark.integration
def test_patched_again_pov_ids(
    detection_c_r2_integration_test_cpv_0: Tuple[Path, Path],
):
    source_directory, detection_path = detection_c_r2_integration_test_cpv_0
    detection = AIxCCChallengeProjectDetection.from_toml(detection_path)
    patch_manager = PatchManager(
        detection.project_name, detection.mode, source_directory
    )

    patch_request = PatchRequest(
        project_name=detection.project_name,
        blobs=[
            BlobInfo(
                blob_data=blob.blob,
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
            )
            for blob in detection.blobs
        ],
        pov_id=UUID("00000000-0000-0000-0000-000000000000"),
        sarif_report=None,
        type=TaskType.full,
    )

    patch_request_2 = PatchRequest(
        project_name=detection.project_name,
        blobs=[
            BlobInfo(
                blob_data=blob.blob,
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
            )
            for blob in detection.blobs
        ],
        pov_id=UUID("00000000-0000-0000-0000-000000000001"),
        sarif_report=None,
        type=TaskType.full,
    )

    patch_manager.add_patch(r2_integration_test_sound_patch_diffs[0], patch_request)
    patched_again_pov_ids = patch_manager.add_patch(
        r2_integration_test_sound_patch_diffs[1], patch_request_2
    )
    assert patched_again_pov_ids == [patch_request.pov_id]
    assert patch_manager.patches == {
        r2_integration_test_sound_patch_diffs[0]: patch_request,
        r2_integration_test_sound_patch_diffs[1]: patch_request_2,
    }


@pytest.mark.integration
def test_mock_c_multiple_cpvs(
    detection_c_mock_c_cpv_0: Tuple[Path, Path],
    detection_c_mock_c_cpv_1: Tuple[Path, Path],
):
    source_directory, detection_cpv_0_path = detection_c_mock_c_cpv_0
    detection_cpv_0 = AIxCCChallengeProjectDetection.from_toml(detection_cpv_0_path)
    patch_manager = PatchManager(
        detection_cpv_0.project_name, detection_cpv_0.mode, source_directory
    )

    patch_request_cpv_0 = PatchRequest(
        project_name=detection_cpv_0.project_name,
        blobs=[
            BlobInfo(
                blob_data=blob.blob,
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
            )
            for blob in detection_cpv_0.blobs
        ],
        pov_id=UUID("00000000-0000-0000-0000-000000000000"),
        sarif_report=None,
        type=TaskType.full,
    )

    _, detection_cpv_1_path = detection_c_mock_c_cpv_1
    detection_cpv_1 = AIxCCChallengeProjectDetection.from_toml(detection_cpv_1_path)

    patch_request_cpv_1 = PatchRequest(
        project_name=detection_cpv_1.project_name,
        blobs=[
            BlobInfo(
                blob_data=blob.blob,
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
            )
            for blob in detection_cpv_1.blobs
        ],
        pov_id=UUID("00000000-0000-0000-0000-000000000001"),
        sarif_report=None,
        type=TaskType.full,
    )

    assert (
        patch_manager.add_patch(mock_c_sound_patch_diffs[0], patch_request_cpv_0) == []
    )
    assert (
        patch_manager.add_patch(mock_c_sound_patch_diffs[1], patch_request_cpv_1) == []
    )

    assert patch_manager.is_pov_blocked(patch_request_cpv_0)
    assert patch_manager.is_pov_blocked(patch_request_cpv_1)
