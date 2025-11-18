from pathlib import Path

import pytest
from crete.atoms.action import HeadAction, VulnerableDiffAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.evaluator.services.default import DefaultEvaluator


@pytest.mark.integration
@pytest.mark.vcr()
@pytest.mark.regression
def test_evaluate_then_clean_code(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
        evaluator=DefaultEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    default_evaluator = DefaultEvaluator()
    diff = rb"""diff --git a/mock_vp.c b/mock_vp.c
index 559df26..54e4013 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -2,6 +2,8 @@
 #include <string.h>
 #include <unistd.h>
 
+#define DEBUG 1
+
 char items[3][10];
 
 void func_a(){
 """

    action = default_evaluator.evaluate(context, diff, detection)
    assert isinstance(action, VulnerableDiffAction)

    # The code should be cleaned up, so the DEBUG macro should be removed.
    assert (
        "#define DEBUG"
        not in (context["pool"].source_directory / "mock_vp.c").read_text()
    )


@pytest.mark.integration
@pytest.mark.regression
@pytest.mark.vcr()
def test_incomplete_fix(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
        evaluator=DefaultEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    # This fix is incomplete as it introduces a new bug.
    diff = rb"""diff --git a/src/http/ngx_http_request.c b/src/http/ngx_http_request.c
index cd26c3e..48f96ab 100644
--- a/src/http/ngx_http_request.c
+++ b/src/http/ngx_http_request.c
@@ -4015,7 +4015,10 @@ ngx_http_process_prefer(ngx_http_request_t *r, ngx_table_elt_t *h,
                       "previous value: \"%V: %V\"",
                       &h->key, &h->value, &r->headers_in.prefer->key,
                       &r->headers_in.prefer->value);
-        ngx_free(r->headers_in.prefer);
+        if (r->headers_in.prefer != NULL) {
+            ngx_free(r->headers_in.prefer);
+            r->headers_in.prefer = NULL;
+        }
         return NGX_OK;
     }
 
"""

    action = context["evaluator"].evaluate(context, diff, detection)
    assert isinstance(action, VulnerableDiffAction)
