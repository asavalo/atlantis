from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.patch_scorer.services.opanai import OpenAIPatchScorer
from python_llm.api.actors import LlmApiManager


@pytest.mark.slow
@pytest.mark.vcr()
def test_openai_patch_scorer(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    vulnerable_diff = r"""diff --git target.c target.c
index 5b3bc13..fa47910 100644
--- target.c
+++ target.c
@@ -1,4 +1,4 @@
 int main() {
-  char buf[100];
+  char buf[200];
   strcpy(buf, argv[1]);
 }
"""

    patch_scorer = OpenAIPatchScorer(
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o")
    )

    score = patch_scorer.score(context, vulnerable_diff)

    assert score == 0.9
