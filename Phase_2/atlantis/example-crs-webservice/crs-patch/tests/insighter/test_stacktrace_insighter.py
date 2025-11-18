from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment_pool.services.oss_fuzz import OssFuzzEnvironmentPool
from crete.framework.evaluator.services.dummy import DummyEvaluator
from crete.framework.insighter.services.stacktrace import StacktraceInsighter
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml

from tests.common.utils import compare_portable_text, mock_insighter_context


@pytest.mark.vcr()
def test_mock_cp(detection_c_mock_cp_cpv_0: tuple[Path, Path]):
    expected_insight = r"""Function: func_a
File: mock_vp.c
Preceding lines:
     4: 
     5: char items[3][10];
     6: 
     7: void func_a(){
     8:     char* buff;
     9:     int i = 0;
    10:     do{
    11:         printf("input item:");
    12:         buff = &items[i][0];
    13:         i++;
Line:
    14:         fgets(buff, 40, stdin);
Following lines:
    15:         buff[strcspn(buff, "\n")] = 0;
    16:     }while(strlen(buff)!=0);
    17:     i--;
    18: }
    19: 
    20: void func_b(){
    21:     char *buff;
    22:     printf("done adding items\n");
    23:     int j;
    24:     printf("display item #:");

"""

    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = StacktraceInsighter(depth=5).create(
        mock_insighter_context(context), detection
    )

    assert actual_insight == expected_insight


@pytest.mark.vcr()
def test_mock_java(detection_jvm_mock_java_cpv_0: tuple[Path, Path]):
    expected_insight = r"""Function: executeCommand
File: src/main/java/com/aixcc/mock_java/App.java
Preceding lines:
     7:  * Hello world!
     8:  *
     9:  */
    10: public class App 
    11: {
    12:     public static void executeCommand(String data) {
    13:         //Only "ls", "pwd", and "echo" commands are allowed.
    14:         try{
    15:             ProcessBuilder processBuilder = new ProcessBuilder();
    16:             processBuilder.command(data);
Line:
    17:             Process process = processBuilder.start();
Following lines:
    18:             process.waitFor();
    19:         } catch (Exception e) {
    20:             e.printStackTrace();
    21:         }
    22:     }
    23: }

"""

    context, detection = AIxCCContextBuilder(
        *detection_jvm_mock_java_cpv_0,
        evaluator=DummyEvaluator(),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = StacktraceInsighter(depth=5).create(
        mock_insighter_context(context), detection
    )

    context["logger"].info(actual_insight)

    assert actual_insight == expected_insight


@pytest.mark.vcr()
@pytest.mark.skip(reason="#884 issue")
def test_annotate_runtime_value(
    detection_c_asc_nginx_cpv_2: tuple[Path, Path],
):
    expected_insight = r"""Function: ngx_decode_base64_internal
File: src/core/ngx_string.c
Preceding lines:
  1320:     if (len % 4 == 1) {
  1321:         return NGX_ERROR;
  1322:     }
  1323: 
  1324:     s = src->data;
  1325:     d = dst->data;
  1326: 
  1327:     while (len > 3) {
  1328:         *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
  1329:         *d++ = (u_char) (basis[s[1]] << 4 | basis[s[2]] >> 2);
Line:
  1330:         *d++ = (u_char) (basis[s[2]] << 6 | basis[s[3]]);
Following lines:
  1331: 
  1332:         s += 4;
  1333:         len -= 4;
  1334:     }
  1335: 
  1336:     if (len > 1) {
  1337:         *d++ = (u_char) (basis[s[0]] << 2 | basis[s[1]] >> 4);
  1338:     }
  1339: 
  1340:     if (len > 2) {
Runtime values in the call line:
  - basis:
    - Value: (const u_char *) 0x555555e043a0 <ngx_decode_base64.basis64> 'M' <repeats 43 times>, ">MMM?456789:;<=MMMMMMM"
    - Type: const unsigned char *
  - d:
    - Value: (u_char *) 0x503000037f12 ""
    - Type: unsigned char *
  - s:
    - Value: (u_char *) 0x525000005129 "OnBhc3NhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"...
    - Type: unsigned char *

Function: ngx_decode_base64
File: src/core/ngx_string.c
Preceding lines:
  1263:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1264:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1265:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1266:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1267:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1268:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1269:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1270:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77
  1271:     };
  1272: 
Line:
  1273:     return ngx_decode_base64_internal(dst, src, basis64);
Following lines:
  1274: }
  1275: 
  1276: 
  1277: ngx_int_t
  1278: ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src)
  1279: {
  1280:     static u_char   basis64[] = {
  1281:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1282:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77,
  1283:         77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 77, 62, 77, 77,
Runtime values in the call line:
  - basis64:
    - Value: 'M' <repeats 43 times>, ">MMM?456789:;<=MMMMMMM\000\001\002\003\004\005\006\a\b\t\n\v\f\r\016\017\020\021\022\023\024\025\026\027\030\031MMMMMM\032\033\034\035\036\037 !\"#$%&'()*+,-./0123", 'M' <repeats 133 times>
    - Type: unsigned char [256]
  - dst:
    - Value: (ngx_str_t *) 0x7ffff7069120
    - Type: struct {
    size_t len;
    u_char *data;
} *
  - ngx_decode_base64_internal:
    - Value: {ngx_int_t (ngx_str_t *, ngx_str_t *, const u_char *)} 0x555555872820 <ngx_decode_base64_internal>
    - Type: long (ngx_str_t *, ngx_str_t *, const u_char *)
  - src:
    - Value: (ngx_str_t *) 0x7ffff7069140
    - Type: struct {
    size_t len;
    u_char *data;
} *

Function: ngx_http_auth_basic_user
File: src/http/ngx_http_core_module.c
Preceding lines:
  1984:         r->headers_in.user.data = (u_char *) "";
  1985:         return NGX_DECLINED;
  1986:     }
  1987: 
  1988:     auth.len = NGX_HTTP_AUTH_MAX;
  1989:     auth.data = ngx_pnalloc(r->pool, auth.len + 1);
  1990:     if (auth.data == NULL) {
  1991:         return NGX_ERROR;
  1992:     }
  1993: 
Line:
  1994:     if (ngx_decode_base64(&auth, &encoded) != NGX_OK) {
Following lines:
  1995:         r->headers_in.user.data = (u_char *) "";
  1996:         return NGX_DECLINED;
  1997:     }
  1998: 
  1999:     auth.data[auth.len] = '\0';
  2000: 
  2001:     for (len = 0; len < auth.len; len++) {
  2002:         if (auth.data[len] == ':') {
  2003:             break;
  2004:         }
Runtime values in the call line:
  - auth:
    - Value: {len = 16, data = 0x503000037f00 "yolo", 'a' <repeats 11 times>, ":p"}
    - Type: struct {
    size_t len;
    u_char *data;
}
  - encoded:
    - Value: {len = 4028, data = 0x525000005115 "eW9sb2FhYWFhYWFhYWFhOnBhc3NhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"...}
    - Type: struct {
    size_t len;
    u_char *data;
}
  - ngx_decode_base64:
    - Value: {ngx_int_t (ngx_str_t *, ngx_str_t *)} 0x5555558727a0 <ngx_decode_base64>
    - Type: long (ngx_str_t *, ngx_str_t *)

Function: ngx_http_variable_remote_user
File: src/http/ngx_http_variables.c
Preceding lines:
  1750:     return NGX_OK;
  1751: }
  1752: 
  1753: 
  1754: static ngx_int_t
  1755: ngx_http_variable_remote_user(ngx_http_request_t *r,
  1756:     ngx_http_variable_value_t *v, uintptr_t data)
  1757: {
  1758:     ngx_int_t  rc;
  1759: 
Line:
  1760:     rc = ngx_http_auth_basic_user(r);
Following lines:
  1761: 
  1762:     if (rc == NGX_DECLINED) {
  1763:         v->not_found = 1;
  1764:         return NGX_OK;
  1765:     }
  1766: 
  1767:     if (rc == NGX_ERROR) {
  1768:         return NGX_ERROR;
  1769:     }
  1770: 
Runtime values in the call line:
  - ngx_http_auth_basic_user:
    - Value: {ngx_int_t (ngx_http_request_t *)} 0x5555559bd0e0 <ngx_http_auth_basic_user>
    - Type: long (ngx_http_request_t *)
  - r:
    - Value: (ngx_http_request_t *) 0x51b000000e80
  - rc:
    - Value: 89404039259008
    - Type: long

Function: ngx_http_get_indexed_variable
File: src/http/ngx_http_variables.c
Preceding lines:
   637: 
   638:     if (ngx_http_variable_depth == 0) {
   639:         ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
   640:                       "cycle while evaluating variable \"%V\"",
   641:                       &v[index].name);
   642:         return NULL;
   643:     }
   644: 
   645:     ngx_http_variable_depth--;
   646: 
Line:
   647:     if (v[index].get_handler(r, &r->variables[index], v[index].data)
Following lines:
   648:         == NGX_OK)
   649:     {
   650:         ngx_http_variable_depth++;
   651: 
   652:         if (v[index].flags & NGX_HTTP_VAR_NOCACHEABLE) {
   653:             r->variables[index].no_cacheable = 1;
   654:         }
   655: 
   656:         return &r->variables[index];
   657:     }
Runtime values in the call line:
  - data:
    - Value: (struct here_cg_arc_record *) 0x0
  - index:
    - Value: 15
    - Type: unsigned long
  - r:
    - Value: (ngx_http_request_t *) 0x51b000000e80
  - v:
    - Value: (ngx_http_variable_t *) 0x51c000002080
"""

    source_directory, detection_toml_file = detection_c_asc_nginx_cpv_2
    challenge_project_detection = AIxCCChallengeProjectDetection.from_toml(
        detection_toml_file
    )
    challenge_project_yaml = AIxCCChallengeProjectYaml.from_project_name(
        challenge_project_detection.project_name
    )

    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_2,
        evaluator=DummyEvaluator(),
        pool=OssFuzzEnvironmentPool(
            challenge_project_directory=source_directory,
            challenge_project_detection=challenge_project_detection,
            challenge_project_yaml=challenge_project_yaml,
            max_timeout=60,
        ),
    ).build(
        previous_action=HeadAction(),
    )

    actual_insight = StacktraceInsighter(depth=5, annotate_runtime_value=True).create(
        mock_insighter_context(context), detection
    )

    assert actual_insight is not None
    assert compare_portable_text(expected_insight, actual_insight)
