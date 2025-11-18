import tempfile
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.vincent.code_inspector import VincentCodeInspector
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder

TEST_SNIPPET_DIRECTORY = Path(__file__).parent / "test_snippets"


def _load_test_snippet(target_name: str) -> str:
    with open(TEST_SNIPPET_DIRECTORY / target_name, "r") as f:
        return f.read()


@pytest.mark.slow
def test_get_references(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        results = code_inspector.get_references("ctx->cookie")

        assert results is not None

        assert len(results) == 3

        assert _load_test_snippet("ngx_http_userid_get_uid") in results[0].snippet.text
        assert _load_test_snippet("ngx_http_userid_set_uid") in results[1].snippet.text
        assert (
            _load_test_snippet("ngx_http_userid_create_uid") in results[2].snippet.text
        )


@pytest.mark.slow
def test_get_references_invalid(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    context["pool"].restore(context)

    with tempfile.TemporaryDirectory(delete=True) as tmp_dir:
        code_inspector = VincentCodeInspector(
            detection_c_asc_nginx_cpv_1[0], Path(tmp_dir), "c"
        )

        results = code_inspector.get_references("invalid_code_target")

        assert results is None
