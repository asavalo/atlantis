from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.analyzer.services.rr_backtrace import RRBacktraceAnalyzer
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator


@pytest.mark.skip(reason="TODO: Support vCPU")
@pytest.mark.slow(reason="TODO: Mock the backtracer")
def test_mock_cp_cpv_1(detection_c_asc_nginx_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    backtracer = RRBacktraceAnalyzer()
    out = backtracer.analyze(context, detection, timeout=10)

    assert out is not None
    assert "func_b" in out["funcs"].keys()


@pytest.mark.skip(reason="TODO: Support vCPU")
@pytest.mark.slow(reason="TODO: Mock the backtracer")
def test_nginx_cpv_10(detection_c_asc_nginx_cpv_10: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    backtracer = RRBacktraceAnalyzer()
    out = backtracer.analyze(context, detection, timeout=10)

    assert out is not None
    assert "ngx_http_userid_set_uid" in out["funcs"].keys()
