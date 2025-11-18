from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.patch_scorer.services.pseudo_code import PseudoCodePatchScorer
from python_llm.api.actors import LlmApiManager


@pytest.mark.vcr()
def test_pseudo_code_patch_scorer(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, _ = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    vulnerable_diff = r"""--- a/mock_vp.c
+++ b/mock_vp.c
@@ -11,7 +11,7 @@
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 10, stdin);
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
"""
    patch_scorer = PseudoCodePatchScorer(
        llm_api_manager=LlmApiManager.from_environment(model="gpt-4o")
    )

    score = patch_scorer.score(context, vulnerable_diff)

    assert 0 <= score <= 1.0
