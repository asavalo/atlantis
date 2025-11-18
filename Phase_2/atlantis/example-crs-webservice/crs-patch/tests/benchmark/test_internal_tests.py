import tempfile
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crete.atoms.report import _run_internal_tests_if_exists  # type: ignore
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from python_aixcc_challenge.project.functions import (
    prepare_aixcc_challenge_projects_from_project_names,
)
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY


def test_internal_tests_mock_cp(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    good_patch = (
        OSS_FUZZ_DIRECTORY
        / "projects/aixcc/c/mock-cp/.aixcc/patches/filein_harness/cpv_1.diff"
    ).read_bytes()

    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    is_sound = _run_internal_tests_if_exists(context, good_patch)

    assert is_sound


DUMMY_DETECTION_TOML_FILE = """
vulnerability_identifier = "custom-c-r3-integration-test-beta-cpv-0-full"
project_name = "aixcc/c/r3-integration-test-beta"
[[blobs]]
harness_name = "fuzz_vuln"
sanitizer_name = "address"
blob = "bmFtZTogQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJCQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJCQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJCQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJCQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJCQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJCQUFBQUJCQkJBQUFBQkJCQkFBQUFCQkJC"

[mode]
type = "full"
base_ref = "fd00e1db80efb2a5b114b0cfb0fd996b9a319e22"

"""


@pytest.mark.skip(reason="oss-fuzz not updated yet (Team-Atlanta/oss-fuzz#141)")
@pytest.mark.slow
def test_internal_tests_integration_test():
    # NOTE: This is tuned for r3 internal test. If the format is changed, this test will fail.
    # Adjust this test if the format is changed.
    GOOD_DIFF = r"""
diff --git a/vuln.c b/vuln.c
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
""".lstrip()
    BAD_DIFF = GOOD_DIFF.replace("MAX_STRLEN", "5")

    [source_directory] = prepare_aixcc_challenge_projects_from_project_names(
        ["aixcc/c/r3-integration-test-beta"],
        DEFAULT_CACHE_DIRECTORY,
    )

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(DUMMY_DETECTION_TOML_FILE.encode())
        f.flush()

        detection_toml_file = Path(f.name)

        context, _detection = AIxCCContextBuilder(
            source_directory,
            detection_toml_file,
            evaluator=MockEvaluator(),
        ).build(
            previous_action=HeadAction(),
        )

        assert context["pool"].internal_test_exists()

        is_sound = _run_internal_tests_if_exists(context, BAD_DIFF.encode())
        assert not is_sound

        is_sound = _run_internal_tests_if_exists(context, GOOD_DIFF.encode())
        assert is_sound
