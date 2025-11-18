import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Tuple
from uuid import UUID

import pytest
from crs_patch.models.models import BlobInfo, PatchRequest, TaskType
from crs_patch.services.patch_checker import PatchChecker
from pytest_mock import MockerFixture
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY

TARGET_PROJECT = "aixcc/c/r2-integration-test"

sound_patch_diff = r"""diff --git a/vuln.c b/vuln.c
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
"""

compilable_patch_diff = r"""diff --git a/vuln.c b/vuln.c
index 15206dc..de6e59b 100644
--- a/vuln.c
+++ b/vuln.c
@@ -26,7 +26,7 @@ bool person_info_parse_file(person_info_t * person_info, const char * const in)
     for (; isspace(in[last_pos]); last_pos++);
 
     // The bug is THE LINE BELOW THIS LINE
-    strcpy(person_info->name, &in[last_pos]);
+    strcpy(person_info->name, "");
 
     return true;
-}
\ No newline at end of file
+}
"""

wrong_patch_diff = r"""--- a/vuln.c
+++ b/vuln.c
@@ -26,7 +26,8 @@
     for (; isspace(in[last_pos]); last_pos++);

     // The bug is THE LINE BELOW THIS LINE
-    strcpy(person_info->name, &in[last_pos]);
+    strncpy(person_info->name, &in[last_pos], MAX_STRLEN - 1);
+    person_info->name[MAX_STRLEN - 1] = '\0';

     return true;
 }
"""

vulnerable_pov_diff = r"""diff --git a/vuln.c b/vuln.c
index 15206dc..df29443 100644
--- a/vuln.c
+++ b/vuln.c
@@ -26,7 +26,8 @@ bool person_info_parse_file(person_info_t * person_info, const char * const in)
     for (; isspace(in[last_pos]); last_pos++);
 
     // The bug is THE LINE BELOW THIS LINE
-    strcpy(person_info->name, &in[last_pos]);
+    strncpy(person_info->name, &in[last_pos], MAX_STRLEN);
+    person_info->name[MAX_STRLEN] = '\0';
 
     return true;
-}
\ No newline at end of file
+}
"""


@pytest.fixture
def patch_checker(
    detection_c_r2_integration_test_cpv_0: Tuple[Path, Path],
) -> PatchChecker:
    source_directory, detection_path = detection_c_r2_integration_test_cpv_0
    detection = AIxCCChallengeProjectDetection.from_toml(detection_path)
    with TemporaryDirectory() as temp_dir:
        patch_checker = PatchChecker()
        patch_checker.temp_dir = Path(temp_dir)  # type: ignore
        patch_checker.source_directory = source_directory
        patch_checker.local_oss_fuzz_directory = OSS_FUZZ_DIRECTORY
        patch_checker.ossfuzz_helper_script = (
            patch_checker.local_oss_fuzz_directory / "infra" / "helper.py"
        )
        patch_checker.restore()
        subprocess.check_call(
            f"git -C {source_directory} checkout {detection.mode.checkout_ref()}",
            shell=True,
        )
        return patch_checker


@pytest.fixture
def patch_request(
    detection_c_r2_integration_test_cpv_0: Tuple[Path, Path],
) -> PatchRequest:
    _, detection_path = detection_c_r2_integration_test_cpv_0
    detection = AIxCCChallengeProjectDetection.from_toml(detection_path)
    patch_request = PatchRequest(
        project_name=detection.project_name,
        blobs=[
            BlobInfo(
                blob_data=detection.blobs[0].blob,
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
            )
            for blob in detection.blobs
        ],
        pov_id=UUID("00000000-0000-0000-0000-000000000000"),
        sarif_report=None,
        type=TaskType.full,
    )
    return patch_request


def test_patch_checker_build_image(patch_checker: PatchChecker):
    assert patch_checker.build_image(TARGET_PROJECT)


def test_patch_checker_sound_patch(
    patch_checker: PatchChecker, patch_request: PatchRequest
):
    assert patch_checker.check_build(TARGET_PROJECT), "Pure build should be successful"
    assert not patch_checker.check_pov(patch_request), (
        "PoV should not be runnable before patch"
    )

    assert patch_checker.check_patch_applicable(sound_patch_diff), (
        "Sound patch should be applicable"
    )
    assert patch_checker.check_build(TARGET_PROJECT, sound_patch_diff), (
        "Sound patch should be buildable"
    )
    assert patch_checker.check_pov(patch_request), "PoV should be runnable after patch"
    assert patch_checker.check_functional_tests(patch_request), (
        "Functional tests should be runnable"
    )


def test_patch_checker_wrong_patch(
    patch_checker: PatchChecker, patch_request: PatchRequest
):
    assert not patch_checker.check_patch_applicable(wrong_patch_diff), (
        "Wrong patch should not be applicable"
    )


def test_patch_checker_vulnerable_pov_patch(
    patch_checker: PatchChecker, patch_request: PatchRequest
):
    assert patch_checker.check_patch_applicable(vulnerable_pov_diff), (
        "Vulnerable POV patch should not be applicable"
    )
    assert patch_checker.check_build(TARGET_PROJECT, vulnerable_pov_diff), (
        "Vulnerable POV patch should be buildable"
    )
    assert not patch_checker.check_pov(patch_request), "PoV should not be runnable"


def test_patch_checker_compilable_patch(
    patch_checker: PatchChecker, patch_request: PatchRequest
):
    assert patch_checker.check_patch_applicable(compilable_patch_diff), (
        "Compilable patch should be applicable"
    )
    assert patch_checker.check_build(TARGET_PROJECT, compilable_patch_diff), (
        "Compilable patch should be buildable"
    )
    assert patch_checker.check_pov(patch_request), "PoV should be runnable"
    assert not patch_checker.check_functional_tests(patch_request), (
        "Functional tests should not be runnable"
    )


# test multiple blobs
def test_patch_checker_run_pov_multiple_blobs_patched(
    patch_checker: PatchChecker,
    patch_request: PatchRequest,
):
    patch_request.blobs = patch_request.blobs * 10
    assert patch_checker.check_build(TARGET_PROJECT, sound_patch_diff), (
        "Patched build should be buildable"
    )
    assert patch_checker.check_pov(patch_request), "PoV should be runnable"


# test multiple blobs
def test_patch_checker_run_pov_multiple_blobs_vulnerable(
    patch_checker: PatchChecker,
    patch_request: PatchRequest,
):
    patch_request.blobs = patch_request.blobs * 10
    assert patch_checker.check_build(TARGET_PROJECT, vulnerable_pov_diff), (
        "Vulnerable POV patch should be buildable"
    )
    assert not patch_checker.check_pov(patch_request), "PoV should not be runnable"


## run_pov error cases
# test TimeoutException
def test_patch_checker_run_pov_timeout(
    patch_checker: PatchChecker, patch_request: PatchRequest, mocker: MockerFixture
):
    mocker.patch("subprocess.check_call", side_effect=subprocess.TimeoutExpired)
    assert patch_checker.check_pov(patch_request), "PoV should be runnable"


# test error code 201
def test_patch_checker_run_pov_error_code_201(
    patch_checker: PatchChecker, patch_request: PatchRequest, mocker: MockerFixture
):
    mocker.patch(
        "subprocess.check_call", side_effect=subprocess.CalledProcessError(201, "")
    )
    assert patch_checker.check_pov(patch_request), "PoV should be runnable"


# test error code 202
def test_patch_checker_run_pov_error_code_202(
    patch_checker: PatchChecker, patch_request: PatchRequest, mocker: MockerFixture
):
    mocker.patch(
        "subprocess.check_call", side_effect=subprocess.CalledProcessError(202, "")
    )
    assert not patch_checker.check_pov(patch_request), (
        "Functional tests should not be runnable"
    )


# test unknown error code
def test_patch_checker_run_pov_unknown_error_code(
    patch_checker: PatchChecker, patch_request: PatchRequest, mocker: MockerFixture
):
    mocker.patch(
        "subprocess.check_call", side_effect=subprocess.CalledProcessError(1, "")
    )
    assert patch_checker.check_pov(patch_request), "PoV should be runnable"


# test unknown exception
def test_patch_checker_run_pov_unknown_exception(
    patch_checker: PatchChecker, patch_request: PatchRequest, mocker: MockerFixture
):
    mocker.patch("subprocess.check_call", side_effect=Exception("Unknown exception"))
    assert patch_checker.check_pov(patch_request), "PoV should be runnable"
