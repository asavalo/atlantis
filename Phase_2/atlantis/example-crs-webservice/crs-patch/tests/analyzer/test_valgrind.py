from pathlib import Path

from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.valgrind import ValgrindAnalyzer
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator


def test_mock_cp_cpv_0(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    valgrind_analyzer = ValgrindAnalyzer()
    report = valgrind_analyzer.analyze(context, detection)

    # Check if a heap summary is provided properly
    assert report is not None
    assert "HEAP SUMMARY" in report
    assert "in use at exit: 24,384,344 bytes in 18 blocks" in report


def test_mock_cp_cpv_1(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    valgrind_analyzer = ValgrindAnalyzer()
    report = valgrind_analyzer.analyze(context, detection)

    # Check if a heap summary is provided properly
    assert report is not None
    assert "HEAP SUMMARY" in report
    assert "in use at exit: 24,384,364 bytes in 20 blocks" in report
