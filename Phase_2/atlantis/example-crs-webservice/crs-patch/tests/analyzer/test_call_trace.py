from pathlib import Path

import pytest

from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.call_trace import CallTraceAnalyzer
from crete.framework.analyzer.services.call_trace.models import FunctionCall
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator


@pytest.mark.slow(reason="This test is slow as it runs a real environment")
def test_call_trace_c(detection_c_babynote_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_babynote_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    call_trace = CallTraceAnalyzer().analyze(context, detection)
    assert call_trace is not None
    assert call_trace[:5] == [
        FunctionCall(
            caller_file=Path("mock_vp.c"),
            caller_name="run_main",
            call_line=176,
            callee_file=Path("mock_vp.c"),
            callee_name="menu",
        ),
        FunctionCall(
            caller_file=Path("mock_vp.c"),
            caller_name="run_main",
            call_line=183,
            callee_file=Path("mock_vp.c"),
            callee_name="create_note",
        ),
        FunctionCall(
            caller_file=Path("mock_vp.c"),
            caller_name="create_note",
            call_line=94,
            callee_file=Path("mock_vp.c"),
            callee_name="read_input",
        ),
        FunctionCall(
            caller_file=Path("mock_vp.c"),
            caller_name="run_main",
            call_line=176,
            callee_file=Path("mock_vp.c"),
            callee_name="menu",
        ),
        FunctionCall(
            caller_file=Path("mock_vp.c"),
            caller_name="run_main",
            call_line=183,
            callee_file=Path("mock_vp.c"),
            callee_name="create_note",
        ),
    ]


@pytest.mark.slow(reason="This test is slow as it runs a real environment")
def test_call_trace_jvm(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=MockEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    call_trace = CallTraceAnalyzer().analyze(context, detection)
    assert call_trace is not None
    assert call_trace == [
        FunctionCall(
            caller_file=Path("src/main/java/com/aixcc/mock_java/App.java"),
            caller_name="com.aixcc.mock_java.App.executeCommand",
            call_line=15,
            callee_file=None,
            callee_name="java.lang.ProcessBuilder.<init>",
        ),
        FunctionCall(
            caller_file=Path("src/main/java/com/aixcc/mock_java/App.java"),
            caller_name="com.aixcc.mock_java.App.executeCommand",
            call_line=16,
            callee_file=None,
            callee_name="java.lang.ProcessBuilder.command",
        ),
        FunctionCall(
            caller_file=Path("src/main/java/com/aixcc/mock_java/App.java"),
            caller_name="com.aixcc.mock_java.App.executeCommand",
            call_line=17,
            callee_file=None,
            callee_name="java.lang.ProcessBuilder.start",
        ),
        FunctionCall(
            caller_file=Path("src/main/java/com/aixcc/mock_java/App.java"),
            caller_name="com.aixcc.mock_java.App.executeCommand",
            call_line=15,
            callee_file=None,
            callee_name="java.lang.ProcessBuilder.<init>",
        ),
        FunctionCall(
            caller_file=Path("src/main/java/com/aixcc/mock_java/App.java"),
            caller_name="com.aixcc.mock_java.App.executeCommand",
            call_line=16,
            callee_file=None,
            callee_name="java.lang.ProcessBuilder.command",
        ),
        FunctionCall(
            caller_file=Path("src/main/java/com/aixcc/mock_java/App.java"),
            caller_name="com.aixcc.mock_java.App.executeCommand",
            call_line=17,
            callee_file=None,
            callee_name="java.lang.ProcessBuilder.start",
        ),
    ]
