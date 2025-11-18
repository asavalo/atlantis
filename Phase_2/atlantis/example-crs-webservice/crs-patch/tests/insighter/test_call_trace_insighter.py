from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.call_trace import CallTraceInsighter

from tests.common.utils import mock_insighter_context


def test_mock_cp(detection_c_mock_cp_cpv_1: tuple[Path, Path]):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    # No call trace found because it fails to find the harness file.
    # The harness file is located in `src/test` not `src/samples`.
    actual_insight = CallTraceInsighter(depth=10).create(
        mock_insighter_context(context), detection
    )
    assert actual_insight is None


@pytest.mark.slow(reason="It is not mockable due to the need for instrumentation.")
@pytest.mark.vcr()
def test_cp_user_babynote(detection_c_babynote_cpv_0: tuple[Path, Path]):
    expected_insight = r"""other functions executed by the bug-triggering input:

  view_note (called by run_main in mock_vp.c:190)
  menu (called by run_main in mock_vp.c:177)
  drop_note (called by run_main in mock_vp.c:188)
  menu (called by run_main in mock_vp.c:177)
  read_input (called by create_note in mock_vp.c:95)
  create_note (called by run_main in mock_vp.c:184)
  menu (called by run_main in mock_vp.c:177)
  read_input (called by create_note in mock_vp.c:95)
  create_note (called by run_main in mock_vp.c:184)
  menu (called by run_main in mock_vp.c:177)
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_babynote_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = CallTraceInsighter(depth=10).create(
        mock_insighter_context(context), detection
    )
    assert actual_insight == expected_insight


@pytest.mark.slow(reason="It is not mockable due to the need for instrumentation.")
@pytest.mark.vcr()
def test_cp_nginx(detection_c_asc_nginx_cpv_10: tuple[Path, Path]):
    expected_insight = r"""other functions executed by the bug-triggering input:

  ngx_alloc (called by ngx_palloc_large in src/core/ngx_palloc.c:220)
  ngx_palloc_large (called by ngx_pnalloc in src/core/ngx_palloc.c:144)
  ngx_pnalloc (called by ngx_http_userid_set_uid in src/http/modules/ngx_http_userid_filter_module.c:424)
  ngx_http_userid_create_uid (called by ngx_http_userid_set_uid in src/http/modules/ngx_http_userid_filter_module.c:386)
  ngx_http_userid_set_uid (called by ngx_http_userid_filter in src/http/modules/ngx_http_userid_filter_module.c:248)
  ngx_decode_base64_internal (called by ngx_decode_base64 in src/core/ngx_string.c:1273)
  ngx_decode_base64 (called by ngx_http_userid_get_uid in src/http/modules/ngx_http_userid_filter_module.c:361)
  ngx_strncasecmp (called by ngx_http_parse_multi_header_lines in src/http/ngx_http_parse.c:1984)
  ngx_http_parse_multi_header_lines (called by ngx_http_userid_get_uid in src/http/modules/ngx_http_userid_filter_module.c:341)
  ngx_alloc (called by ngx_palloc_large in src/core/ngx_palloc.c:220)
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = CallTraceInsighter(depth=10).create(
        mock_insighter_context(context), detection
    )
    assert actual_insight == expected_insight


@pytest.mark.slow(reason="It is not mockable due to the need for instrumentation.")
@pytest.mark.vcr()
def test_indirect_call(detection_c_asc_nginx_cpv_9: tuple[Path, Path]):
    expected_insight = r"""other functions executed by the bug-triggering input:

  ngx_http_set_exten (called by ngx_http_script_regex_end_code in src/http/ngx_http_script.c:1299)
  ngx_http_script_regex_end_code (called by ngx_http_rewrite_handler in src/http/modules/ngx_http_rewrite_module.c:180)
  ngx_http_script_copy_capture_code (called by ngx_http_rewrite_handler in src/http/modules/ngx_http_rewrite_module.c:180)
  ngx_http_script_copy_code (called by ngx_http_rewrite_handler in src/http/modules/ngx_http_rewrite_module.c:180)
  ngx_alloc (called by ngx_palloc_large in src/core/ngx_palloc.c:220)
  ngx_palloc_large (called by ngx_pnalloc in src/core/ngx_palloc.c:144)
  ngx_pnalloc (called by ngx_http_script_regex_start_code in src/http/ngx_http_script.c:1179)
  ngx_regex_exec (called by ngx_http_regex_exec in src/http/ngx_http_variables.c:2648)
  ngx_alloc (called by ngx_palloc_large in src/core/ngx_palloc.c:220)
  ngx_palloc_large (called by ngx_palloc in src/core/ngx_palloc.c:131)
"""

    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_9,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = CallTraceInsighter(depth=10).create(
        mock_insighter_context(context), detection
    )
    assert actual_insight == expected_insight
