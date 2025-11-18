from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.coder.services.aider import AiderCoder
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from python_llm.api.actors import LlmApiManager
from crete.framework.coder.services.aider import DiffTracker


@pytest.mark.skip(reason="Skipping test .cache dir is changed")
def test_multiple_runs(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    coder = AiderCoder(
        agent_context=context,
        detection=detection,
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o"),
        target_files=[context["pool"].source_directory / "mock_vp.c"],
    )

    first_diff = coder.run(
        context, "Add a comment '// 0xdeadbeef' to the function func_a"
    )
    assert first_diff is not None, "First diff should not be None"
    assert "0xdeadbeef" in first_diff.decode(), "First diff should contain '0xdeadbeef'"

    second_diff = coder.run(
        context, "Add a comment '// 0xbadc0de' to the function func_b"
    )
    assert second_diff is not None, "Second diff should not be None"
    assert "0xdeadbeef" in second_diff.decode(), (
        "Second diff should contain '0xdeadbeef'"
    )
    assert "0xbadc0de" in second_diff.decode(), "Second diff should contain '0xbadc0de'"


def test_git_diff_without_newline_at_end_of_file(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    diff_tracker = DiffTracker(
        source_directory=context["pool"].source_directory,
        llm_history_file=None,
    )

    diff_tracker._original_contents[str(context["pool"].source_directory / "test")] = (  # type: ignore[reportPrivateUsage]
        "int main() { return 0; }"
    )
    diff_tracker.write_text(
        str(context["pool"].source_directory / "test"), "int main() { return 1; }\n"
    )

    assert (
        diff_tracker.git_diff()
        == "--- a/test\n+++ b/test\n@@ -1 +1 @@\n-int main() { return 0; }\n\\ No newline at end of file\n+int main() { return 1; }\n"
    )
