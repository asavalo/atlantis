import tempfile
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.vincent.code_inspector import VincentCodeInspector
from crete.framework.agent.services.vincent.code_inspector.models import CodeQueryResult
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.mock import MockEvaluator
from crete.framework.language_parser.services.ctags import CtagEntry

TEST_SNIPPET_DIRECTORY = Path(__file__).parent / "test_snippets"


def _load_test_snippet(target_name: str) -> str:
    with open(TEST_SNIPPET_DIRECTORY / target_name, "r") as f:
        return f.read()


def _test_one_snippet(code_inspector: VincentCodeInspector, target_name: str):
    results = code_inspector.get_definition(target_name)

    assert results is not None
    assert len(results) == 1
    result = results[0]

    assert result.snippet.text == _load_test_snippet(target_name)


def _is_success(query_results: list[CodeQueryResult], pattern: str) -> bool:
    for query_result in query_results:
        if pattern in query_result.snippet.text:
            # print(query_result.snippet)
            return True

    return False


def _test_with_tag_entries(
    code_inspector: VincentCodeInspector, test_target_entries: list[CtagEntry]
):
    # print(len(test_target_entries))

    for entry in test_target_entries:
        results = code_inspector.get_definition(entry.name)

        assert results is not None
        if _is_success(results, entry.pattern):
            continue

        assert False, f'"{entry.pattern}" is not found for "{entry.name}"'


@pytest.mark.slow
def test_get_function_definition(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        _test_one_snippet(code_inspector, "ngx_http_process_request")
        _test_one_snippet(code_inspector, "ngx_http_script_flush_complex_value")


@pytest.mark.slow
def test_get_variable_definition(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        _test_one_snippet(code_inspector, "ngx_http_client_errors")


@pytest.mark.slow
def test_get_struct_or_union_definition(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        _test_one_snippet(code_inspector, "ngx_event_pipe_s")


@pytest.mark.slow
def test_get_typedef_definition(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        _test_one_snippet(code_inspector, "ngx_openssl_conf_t")
        _test_one_snippet(code_inspector, "ngx_event_ovlp_t")


@pytest.mark.slow
def test_get_macro_definition(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        _test_one_snippet(code_inspector, "NGX_HTTP_GET")


@pytest.mark.slow
def test_get_enum_definition(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        _test_one_snippet(code_inspector, "ngx_http_state_e")


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_functions_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_functions()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_variables_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_variables()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_structs_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_structs_or_unions()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_typedefs_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_typedefs()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_macros_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_macros()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_enums_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_enums()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_enumerators_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_enumerators()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.slow(reason="This test is slow due to a lot of testcases")
def test_against_all_members_in_nginx(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        entries = code_inspector.ctags_parser.get_all_members()

        _test_with_tag_entries(code_inspector, entries)


@pytest.mark.skip(reason="comment-inclusion feature was temporarily disabled")
def test_comment_expansion(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=MockEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_1),
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        query_results = code_inspector.get_definition("NGX_HTTP_CLIENT_CLOSED_REQUEST")

        assert query_results is not None
        assert len(query_results) == 1

        comment_snippet = (
            "* HTTP does not define the code for the case when a client closed"
        )

        for query_result in query_results:
            assert comment_snippet in query_result.snippet.text
