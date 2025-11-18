from pathlib import Path

import pytest
from crete.atoms.action import (
    CompilableDiffAction,
    HeadAction,
    NoPatchAction,
    VulnerableDiffAction,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.coderover_k import (
    CodeRoverKFaultLocalizer,
    NoPatchReason,
    _has_bug_class_changed,  # type: ignore
    _make_delta_mode_ref_diff_section,  # type: ignore
    _make_feedback_prompt,  # type: ignore
)
from python_llm.api.actors import LlmApiManager

from tests.common.utils import mock_fault_localization_context


@pytest.mark.vcr()
def test_mock_cp(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    fault_locations = (
        CodeRoverKFaultLocalizer(
            analysis_llm=LlmApiManager.from_environment(model="gpt-4o"),
            parsing_llm=LlmApiManager.from_environment(model="gpt-4o"),
        )
        .localize(mock_fault_localization_context(context), detection)
        .locations
    )

    assert fault_locations == [
        FaultLocation(
            file=context["pool"].source_directory / "mock_vp.c",
            function_name="func_a",
            line_range=None,
        )
    ]


@pytest.mark.vcr()
def test_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    fault_locations = (
        CodeRoverKFaultLocalizer(
            analysis_llm=LlmApiManager.from_environment(model="gpt-4o"),
            parsing_llm=LlmApiManager.from_environment(model="gpt-4o"),
        )
        .localize(mock_fault_localization_context(context), detection)
        .locations
    )

    assert fault_locations == [
        FaultLocation(
            file=context["pool"].source_directory
            / "src/main/java/com/aixcc/mock_java/App.java",
            function_name="executeCommand",
            line_range=None,
        )
    ]


def test_make_feedback_prompt_no_patch():
    test_data_dir = Path(__file__).parent / "test_data"
    expected = (test_data_dir / "expected_feedback_prompt_no_patch.txt").read_text()
    actual = _make_feedback_prompt(
        NoPatchAction(),
        bug_class_changed=False,
        no_patch_reason=NoPatchReason.OTHER,
    )
    assert actual == expected


def test_make_feedback_prompt_compilable():
    test_data_dir = Path(__file__).parent / "test_data"
    expected = (test_data_dir / "expected_feedback_prompt_compilable.txt").read_text()
    actual = _make_feedback_prompt(
        CompilableDiffAction(diff=b"DIFF", stdout=b"STDOUT", stderr=b"STDERR"),
        bug_class_changed=False,
        no_patch_reason=None,
    )
    assert actual == expected


def test_make_feedback_prompt_vulnerable_same_bug():
    test_data_dir = Path(__file__).parent / "test_data"
    expected = (
        test_data_dir / "expected_feedback_prompt_vulnerable_same_bug.txt"
    ).read_text()
    actual = _make_feedback_prompt(
        VulnerableDiffAction(diff=b"DIFF", stdout=b"STDOUT", stderr=b"STDERR"),
        bug_class_changed=False,
        no_patch_reason=None,
    )
    assert actual == expected


def test_make_feedback_prompt_vulnerable_new_bug():
    test_data_dir = Path(__file__).parent / "test_data"
    expected = (
        test_data_dir / "expected_feedback_prompt_vulnerable_new_bug.txt"
    ).read_text()
    actual = _make_feedback_prompt(
        VulnerableDiffAction(diff=b"DIFF", stdout=b"STDOUT", stderr=b"STDERR"),
        bug_class_changed=True,
        no_patch_reason=None,
    )
    assert actual == expected


def test_has_bug_class_changed():
    test_data_dir = Path(__file__).parent / "test_data"
    crash_0_heap_uaf_log = (test_data_dir / "crash_0_heap_uaf.log").read_text()
    crash_1_heap_bof_log = (test_data_dir / "crash_1_heap_bof.log").read_text()
    crash_2_heap_bof_log = (test_data_dir / "crash_2_heap_bof.log").read_text()

    assert _has_bug_class_changed(crash_0_heap_uaf_log, crash_1_heap_bof_log)
    assert not _has_bug_class_changed(crash_1_heap_bof_log, crash_2_heap_bof_log)


def test_make_delta_mode_ref_diff_section(
    detection_c_mock_c_cpv_0_delta: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0_delta,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    ref_diff_section = _make_delta_mode_ref_diff_section(
        mock_fault_localization_context(context), detection
    )
    assert (
        ref_diff_section
        == r"""## Bug Introduced Diff

Before the following diff, the bug was not introduced.
But after the following diff, the bug is introduced.
Refer to the diff to find the bug location.
Note that the bug could exist in the diff or in other code related to the diff.

<ref_diff>
diff --git a/mock.c b/mock.c
index 0375dba..b7ec61d 100644
--- a/mock.c
+++ b/mock.c
@@ -5,8 +5,21 @@
 // Without this, target_1 and target_2 will be optimized as NOP functions.
 #pragma clang optimize off
 
-void process_input_header(const uint8_t *data, size_t size) {}
+void process_input_header(const uint8_t *data, size_t size) {
+  char buf[0x40];
+  if (size > 0 && data[0] == 'A')
+      memcpy(buf, data, size);
+}
 
-void parse_buffer_section(const uint8_t *data, size_t size) {}
+void parse_buffer_section(const uint8_t *data, size_t size) {
+  if (size < 0x8 || size > 0x100)
+    return;
+  uint32_t buf_size = ((uint32_t *)data)[0];
+  uint32_t idx = ((uint32_t *)data)[1];
+  if (buf_size + 8 != size)
+    return;
+  uint8_t *buf = (uint8_t *)malloc(buf_size);
+  memcpy(&buf[idx], &data[8],  buf_size);
+}
 
 #pragma clang optimize on

</ref_diff>"""
    )
