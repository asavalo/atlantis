import tempfile
from pathlib import Path
from unittest import mock

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment.services.oss_fuzz.cached import (
    CachedOssFuzzEnvironment,
)
from crete.framework.evaluator.services.default import DefaultEvaluator


@pytest.mark.slow
@pytest.mark.timeout(3 * 60)
def test_issue_1169(
    detection_c_r2_libxml2_cpv_0: tuple[Path, Path], tmpdir_as_path: Path
):
    diff = b"""
diff --git a/parser.c b/parser.c
index 836b4a4f..6fb242cf 100644
--- a/parser.c
+++ b/parser.c
@@ -3994,18 +3994,20 @@ xmlExpandPEsInEntityValue(xmlParserCtxtPtr ctxt, xmlSBuf *buf,
             if ( str[1] == '%') {
                 str++;                
                 xmlEntityPtr ent;
+                int nameLen;
 
                 ent = xmlParseStringPEReference(ctxt, &str);
                 if (ent == NULL) {
                     return;
                 }
 
-                // Grow the buffer to handle the input
-                xmlSBufGrow(buf, str - chunk);
-                xmlSBufAddEntitySecure(buf, ent->name, ent->length);
+                nameLen = xmlStrlen(ent->name);
+                if (nameLen == 0)
+                    return;
+
+                xmlSBufAddEntitySecure(buf, ent->name, nameLen);
 
                 chunk = str;
-            } else {
                 /* Normal ASCII char */
                 if (!IS_BYTE_CHAR(c)) {
                     xmlFatalErrMsg(ctxt, XML_ERR_INVALID_CHAR,
"""
    with mock.patch(
        "crete.framework.environment.services.oss_fuzz.default.OssFuzzEnvironment._from_elapsed_time_to_timeout",
        return_value=30,
    ):
        context, detection = AIxCCContextBuilder(
            *detection_c_r2_libxml2_cpv_0,
            evaluator=DefaultEvaluator(),
            environment_pool_directory=tmpdir_as_path,
        ).build(previous_action=HeadAction())

        environment = context["pool"].use(context, "CLEAN")
        assert isinstance(environment, CachedOssFuzzEnvironment)

        context["evaluator"].evaluate(
            context,
            diff,
            detection,
        )


@pytest.mark.slow
def test_slow_yet_correct_patch(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    # This patch ensures that the patch is correct yet slow.
    # We expect that the patch is considered as correct (i.e., run_pov is successful).
    diff = r"""diff --git a/mock_vp.c b/mock_vp.c
index 559df26..bb733a2 100644
--- a/mock_vp.c
+++ b/mock_vp.c
@@ -7,11 +7,13 @@ char items[3][10];
 void func_a(){
     char* buff;
     int i = 0;
+    sleep(1);
     do{
         printf("input item:");
         buff = &items[i][0];
         i++;
-        fgets(buff, 40, stdin);
+        fgets(buff, 9, stdin);
+        if (i==3){buff[0]= 0;}
         buff[strcspn(buff, "\n")] = 0;
     }while(strlen(buff)!=0);
     i--;
"""

    # NOTE: Reduce the timeout to 30 seconds to speed up the test
    with mock.patch(
        "crete.framework.environment.services.oss_fuzz.default.RUN_POV_TIMEOUT", 30
    ):
        context, detection = AIxCCContextBuilder(
            *detection_c_mock_cp_cpv_0,
            evaluator=DefaultEvaluator(),
        ).build(previous_action=HeadAction())

    environment = context["pool"].restore(context)
    with tempfile.NamedTemporaryFile() as f:
        f.write(bytes(diff, "utf-8"))
        f.flush()

        environment.patch(context, Path(f.name))
    environment.run_pov(context, detection)
