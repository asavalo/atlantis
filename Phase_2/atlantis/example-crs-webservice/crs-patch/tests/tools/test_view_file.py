from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.tools.services import ViewFileTool


def test_view_file_without_line_numbers(
    detection_c_mock_c_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=MockEvaluator(),
    ).build(previous_action=HeadAction())

    with_line_number = False
    file_path = Path(context["pool"].source_directory / "mock.c")

    view_file_tool = ViewFileTool(context, with_line_number)
    content = view_file_tool._run(file_path)  # type: ignore
    lines = content.rstrip().split("\n")
    context["logger"].info(lines)
    assert len(lines) == 25
    assert lines[0] == '#include "mock.h"'
    assert lines[-1] == "#pragma clang optimize on"


def test_view_entire_file_with_line_no(
    detection_c_mock_c_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=MockEvaluator(),
    ).build(previous_action=HeadAction())

    with_line_number = True
    file_path = Path(context["pool"].source_directory / "mock.c")

    view_file_tool = ViewFileTool(context, with_line_number)
    content = view_file_tool._run(file_path)  # type: ignore
    lines = content.rstrip().split("\n")
    context["logger"].info(lines)
    assert len(lines) == 25
    assert lines[0] == '     1: #include "mock.h"'
    assert lines[-1] == "    25: #pragma clang optimize on"


def test_view_file_with_offset_and_line_numbers(
    detection_c_mock_c_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=MockEvaluator(),
    ).build(previous_action=HeadAction())

    with_line_number = True
    offset = 10
    file_path = Path(context["pool"].source_directory / "mock.c")

    view_file_tool = ViewFileTool(context, with_line_number)
    content = view_file_tool._run(file_path, offset)  # type: ignore
    lines = content.rstrip().split("\n")
    context["logger"].info(lines)
    assert len(lines) == 16
    assert lines[0] == "    10:   if (size > 0 && data[0] == 'A')"
    assert lines[-1] == "    25: #pragma clang optimize on"


def test_view_file_with_offset_limit_and_line_numbers(
    detection_c_mock_c_cpv_0: tuple[Path, Path],
):
    context, _detection = AIxCCContextBuilder(
        *detection_c_mock_c_cpv_0,
        evaluator=MockEvaluator(),
    ).build(previous_action=HeadAction())

    with_line_number = True
    offset = 10
    limit = 10
    file_path = Path(context["pool"].source_directory / "mock.c")

    view_file_tool = ViewFileTool(context, with_line_number)
    content = view_file_tool._run(file_path, offset, limit)  # type: ignore
    lines = content.rstrip().split("\n")
    context["logger"].info(lines)
    assert len(lines) == 10

    assert lines[0] == "    10:   if (size > 0 && data[0] == 'A')"
    assert lines[-1] == "    19:   if (buf_size + 8 != size)"
