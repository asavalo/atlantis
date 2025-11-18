from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.mock import MockEnvironmentPool
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.retriever.services.block_statement import BlockStatementRetriever
from python_llm.api.actors import LlmApiManager


@pytest.mark.slow
@pytest.mark.vcr()
def test_block_statement_retriever_retrieve(
    detection_c_asc_nginx_cpv_9: tuple[Path, Path],
):
    text = """{
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "the rewritten URI is too long");
            e->ip = ngx_http_script_exit;
            e->status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }"""

    llm_api_manager = LlmApiManager.from_environment(model="gpt-4o")

    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_9,
        evaluator=DummyEvaluator(),
        pool=MockEnvironmentPool(*detection_c_asc_nginx_cpv_9),
    ).build(
        previous_action=HeadAction(),
    )

    block_statement_retriever = BlockStatementRetriever(
        top_k=5,
        api_key=llm_api_manager.api_key,
        base_url=llm_api_manager.base_url,
    )

    docs = block_statement_retriever.retrieve(context, detection, text)

    assert len(docs) == 5
