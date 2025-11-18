import json
from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.vincent.functions import extract_patches_from_chat
from crete.framework.agent.services.vincent.nodes.patchers.models import PatchSegment
from crete.framework.agent.services.vincent.nodes.patchers.patcher import (
    Patcher,
    _search_lines_and_replace,  # pyright: ignore[reportPrivateUsage]
)
from crete.framework.agent.services.vincent.nodes.patchers.test_feedback import (
    _get_jvm_maven_test_log,  # pyright: ignore[reportPrivateUsage]
)
from crete.framework.agent.services.vincent.nodes.patchers.compile_feedback import (
    _extract_build_errors_jvm,  # pyright: ignore[reportPrivateUsage]
    _extract_build_errors_c,  # pyright: ignore[reportPrivateUsage]
)
from crete.framework.agent.services.vincent.states.patch_state import (
    PatchStage,
    PatchState,
)
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from python_llm.api.actors import LlmApiManager

TEST_REPORT_DIRECTORY = Path(__file__).parent / "test_reports"
TEST_DIFF_DIRECTORY = Path(__file__).parent / "test_diffs"
TEST_MESSAGES_DIRECTORY = Path(__file__).parent / "test_messages"
TEST_LOG_DIRECTORY = Path(__file__).parent / "test_logs"


def _load_test_report(target_name: str) -> str:
    with open(TEST_REPORT_DIRECTORY / target_name, "r") as f:
        return f.read()


def _load_test_log(target_name: str) -> str:
    with open(TEST_LOG_DIRECTORY / target_name, "r") as f:
        return f.read()


@pytest.mark.slow
def test_extract_patches_from_chat(
    detection_c_asc_nginx_cpv_10: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_10,
    ).build(
        previous_action=HeadAction(),
    )

    patcher = Patcher(LlmApiManager.from_environment(model="gpt-4o"))
    patcher.set_context_and_detection(context, detection)

    patches_per_srcfile = extract_patches_from_chat(
        _load_test_report("nginx-cpv-10-report-uncompilable.txt")
    )

    test_patches = {
        "src/http/modules/ngx_http_userid_filter_module.c": [
            PatchSegment(
                patch_tag="[PATCH:`src/http/modules/ngx_http_userid_filter_module.c`:341-343]",
                filename="src/http/modules/ngx_http_userid_filter_module.c",
                patch_code="    cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,\n                                             &conf->name, &ctx->cookie);\n    if (cookie == NULL || ctx->cookie.len == 0) {\n        return ctx;\n    }\n",
                start_line=341,
                end_line=343,
            ),
            PatchSegment(
                patch_tag="[PATCH:`src/http/modules/ngx_http_userid_filter_module.c`:445-449]",
                filename="src/http/modules/ngx_http_userid_filter_module.c",
                patch_code="    } else {\n        if (ctx->cookie.len < 22) {\n            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,\n                         \"userid cookie length is less than 22 bytes\");\n            return NGX_ERROR;\n        }\n        p = ngx_cpymem(p, ctx->cookie.data, 22);\n        *p++ = conf->mark;\n        *p++ = '=';\n    }\n",
                start_line=445,
                end_line=449,
            ),
        ]
    }

    assert test_patches == patches_per_srcfile


def test_extract_patches_from_chat_duplicate_segments(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    patcher = Patcher(LlmApiManager.from_environment(model="gpt-4o"))
    patcher.set_context_and_detection(context, detection)

    patches_per_srcfile = extract_patches_from_chat(
        _load_test_report("duplicate-segments-report.txt")
    )

    test_patches = {
        "libfreerdp/core/client.h": [
            PatchSegment(
                patch_tag="[PATCH:`libfreerdp/core/client.h`:39-41]",
                filename="libfreerdp/core/client.h",
                patch_code="""#ifdef CHANNEL_MAX_COUNT
#undef CHANNEL_MAX_COUNT
#endif
#define CHANNEL_MAX_COUNT 30
""",
                start_line=39,
                end_line=41,
            )
        ],
        "libfreerdp/core/mcs.h": [
            PatchSegment(
                patch_tag="[PATCH:`libfreerdp/core/mcs.h`:4-4]",
                filename="libfreerdp/core/mcs.h",
                patch_code="""#include <freerdp/types.h>
// Ensure FreeRDP's core CHANNEL_MAX_COUNT (30) definition from client.h is authoritative,
// by including client.h after types.h (which might include winpr/wtsapi.h's version).
#include <freerdp/client.h>
""",
                start_line=4,
                end_line=4,
            ),
        ],
    }

    assert test_patches == patches_per_srcfile


def test_verify_patch_segments(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    patcher = Patcher(LlmApiManager.from_environment(model="gpt-4o"))
    patcher.set_context_and_detection(context, detection)

    assert (
        len(
            patcher._verify_patch_segments(  # pyright: ignore[reportPrivateUsage]
                [
                    PatchSegment(
                        patch_tag="[PATCH:`mock_vp.c`:2-3]",
                        filename="mock_vp.c",
                        patch_code="dummy",
                        start_line=2,
                        end_line=3,
                    ),
                ]
            )
        )
        == 0
    )

    failures = patcher._verify_patch_segments(  # pyright: ignore[reportPrivateUsage]
        [
            PatchSegment(
                patch_tag="[PATCH:`dummy`:6-6]",
                filename="dummy",
                patch_code="dummy",
                start_line=6,
                end_line=6,
            ),
        ]
    )

    assert len(failures) == 1
    assert (
        failures[0].reason
        == 'Patch target file (`dummy`) in "[PATCH:`dummy`:6-6]" does not follow the rule. Make sure that `filename` in each segment is valid and relative to the target repository. Use the "filepath" information obtained by the previous [REQUEST:type] requests as the ground truth.'
    )

    failures = patcher._verify_patch_segments(  # pyright: ignore[reportPrivateUsage]
        [
            PatchSegment(
                patch_tag="[PATCH:`mock_vp.c`:7-6]",
                filename="mock_vp.c",
                patch_code="dummy",
                start_line=7,
                end_line=6,
            ),
        ]
    )

    assert len(failures) == 1
    assert (
        failures[0].reason
        == 'The start line number (7) in the "[PATCH:`mock_vp.c`:7-6]" is greater than the end line number (6).'
    )

    failures = patcher._verify_patch_segments(  # pyright: ignore[reportPrivateUsage]
        [
            PatchSegment(
                patch_tag="[PATCH:`mock_vp.c`:6-999]",
                filename="mock_vp.c",
                patch_code="dummy",
                start_line=6,
                end_line=999,
            ),
        ]
    )

    assert len(failures) == 1
    assert (
        failures[0].reason
        == 'The line number (999) in "[PATCH:`mock_vp.c`:6-999]" exceeds the total line count (41) of `mock_vp.c`.'
    )

    failures = patcher._verify_patch_segments(  # pyright: ignore[reportPrivateUsage]
        [
            PatchSegment(
                patch_tag="[PATCH:`mock_vp.c`:6-8]",
                filename="mock_vp.c",
                patch_code="dummy",
                start_line=6,
                end_line=8,
            ),
            PatchSegment(
                patch_tag="[PATCH:`mock_vp.c`:7-8]",
                filename="mock_vp.c",
                patch_code="dummy",
                start_line=7,
                end_line=8,
            ),
        ]
    )

    assert len(failures) == 1
    assert (
        failures[0].reason
        == 'The patch segment "[PATCH:`mock_vp.c`:6-8]" (end line: 8) overlaps the next segment "[PATCH:`mock_vp.c`:7-8]" (start line: 7).'
    )


def test_patch_history(
    detection_c_mock_cp_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_mock_cp_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )

    patcher = Patcher(LlmApiManager.from_environment(model="gpt-4o"))
    patcher.set_context_and_detection(context, detection)

    patches_per_srcfile = extract_patches_from_chat(
        _load_test_report("mock-cp-cpv-1-report-sound.txt")
    )
    assert patches_per_srcfile is not None

    patcher._get_diff_from_patches_dict(patches_per_srcfile)  # pyright: ignore[reportPrivateUsage]

    diff, failures = patcher._get_diff_from_patches_dict(patches_per_srcfile)  # pyright: ignore[reportPrivateUsage]

    assert len(patcher.patch_history) == 1
    assert diff is None
    assert failures is not None
    assert len(failures) == 1
    assert (
        failures[0].reason
        == "You just submitted an identical patch to the previous one. You must provide a different patch for every patching attempts. If you have no choice but to generate the identical patch, analyze the project again and identify the completely different root cause that can explain the issue. Then, provide me with a full patch report with a different approach."
    )


def test_search_lines_and_replace_multiple():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_string = """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""

    patches = [
        PatchSegment(
            patch_tag="",
            filename="dummy",
            patch_code=patch_string,
            start_line=2,
            end_line=3,
        ),
        PatchSegment(
            patch_tag="",
            filename="dummy",
            patch_code=patch_string,
            start_line=6,
            end_line=6,
        ),
    ]

    assert (
        _search_lines_and_replace(original_src, patches)
        == """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
7:GGGGGGGGGGGGGGGGGGGGGG
"""
    )


def test_search_lines_and_replace_overlap():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_string = """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""

    patches = [
        PatchSegment(
            patch_tag="",
            filename="dummy",
            patch_code=patch_string,
            start_line=2,
            end_line=3,
        ),
        PatchSegment(
            patch_tag="",
            filename="dummy",
            patch_code=patch_string,
            start_line=3,
            end_line=6,
        ),
    ]

    assert _search_lines_and_replace(original_src, patches) is None


def test_search_lines_and_replace():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_string = """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""

    patch_result = PatchSegment(
        patch_tag="",
        filename="dummy",
        patch_code=patch_string,
        start_line=3,
        end_line=5,
    )

    assert (
        _search_lines_and_replace(original_src, [patch_result])
        == """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""
    )


def test_search_lines_and_replace_invalid():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_result = PatchSegment(
        patch_tag="", filename="dummy", patch_code="dummy", start_line=0, end_line=7
    )

    assert _search_lines_and_replace(original_src, [patch_result]) is None

    patch_result = PatchSegment(
        patch_tag="", filename="dummy", patch_code="dummy", start_line=5, end_line=3
    )

    assert _search_lines_and_replace(original_src, [patch_result]) is None

    patch_result = PatchSegment(
        patch_tag="", filename="dummy", patch_code="dummy", start_line=8, end_line=9
    )

    assert _search_lines_and_replace(original_src, [patch_result]) is None


def test_search_lines_and_replace_total():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_string = """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""

    patch_result = PatchSegment(
        patch_tag="",
        filename="dummy",
        patch_code=patch_string,
        start_line=1,
        end_line=7,
    )

    assert (
        _search_lines_and_replace(original_src, [patch_result])
        == """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""
    )


def test_search_lines_and_replace_last_line():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_string = """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""

    patch_result = PatchSegment(
        patch_tag="",
        filename="dummy",
        patch_code=patch_string,
        start_line=7,
        end_line=7,
    )

    assert (
        _search_lines_and_replace(original_src, [patch_result])
        == """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""
    )


def test_search_lines_and_replace_sequential():
    original_src = """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
3:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
4:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
5:EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE
6:FFFFFFFFFFFFFFFFFFFFF
7:GGGGGGGGGGGGGGGGGGGGGG
"""

    patch_string_1 = """\
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
"""

    patch_string_2 = """\
------------- Replaced lines -------------
LLLLLLLLLLLLLLLLLL
MMMMMMMMMMMMMMMMMM
NNNNNNNNNNNNNNNNNN
------------- Replaced lines -------------
"""

    patch_result_1 = PatchSegment(
        patch_tag="",
        filename="dummy",
        patch_code=patch_string_1,
        start_line=3,
        end_line=4,
    )

    patch_result_2 = PatchSegment(
        patch_tag="",
        filename="dummy",
        patch_code=patch_string_2,
        start_line=5,
        end_line=6,
    )

    assert (
        _search_lines_and_replace(original_src, [patch_result_1, patch_result_2])
        == """\
1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
------------- Replaced lines -------------
XXXXXXXXXXXXXXXX
YYYYYYYYYYYYYYYY
ZZZZZZZZZZZZZZZZ
------------- Replaced lines -------------
------------- Replaced lines -------------
LLLLLLLLLLLLLLLLLL
MMMMMMMMMMMMMMMMMM
NNNNNNNNNNNNNNNNNN
------------- Replaced lines -------------
7:GGGGGGGGGGGGGGGGGGGGGG
"""
    )


def _reconstruct_messages(messages_name: str) -> list[BaseMessage]:
    with open(
        TEST_MESSAGES_DIRECTORY / messages_name,
        "r",
    ) as f:
        history = json.load(f)

    # reconstruct mock-PatchState
    messages: list[BaseMessage] = []
    for each_m in history["messages"]:
        if each_m["role"] == "system":
            messages.append(SystemMessage(each_m["content"]))  # pyright: ignore[reportUnknownMemberType]
        elif each_m["role"] == "assistant":
            messages.append(AIMessage(each_m["content"]))  # pyright: ignore[reportUnknownMemberType]
        elif each_m["role"] == "user":
            messages.append(HumanMessage(each_m["content"]))  # pyright: ignore[reportUnknownMemberType]

    return messages


@pytest.mark.skip(reason="beanutils image is not available")
@pytest.mark.slow
@pytest.mark.vcr()
def test_generate_patch_diff_against_invalid_report(
    detection_jvm_beanutils_cpv_0: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_jvm_beanutils_cpv_0,
    ).build(
        previous_action=HeadAction(),
    )

    patcher = Patcher(
        LlmApiManager.from_environment(
            model="claude-3-5-sonnet-20241022", custom_llm_provider="anthropic"
        )
    )
    patcher.set_context_and_detection(context, detection)
    patcher.is_instructed = True

    patch_state = PatchState(
        patch_stage=PatchStage.PATCH,
        messages=_reconstruct_messages("invalid_report_messages.json"),
        diff=b"",
        detection=detection,
        requests=[],
        action=HeadAction(),
        feedback_cnt=0,
    )

    assert patcher._generate_patch_diff(patch_state) is not None  # pyright: ignore[reportPrivateUsage]


def test_get_jvm_maven_test_log():
    assert (
        _get_jvm_maven_test_log(_load_test_log("jvm_test_log.txt"))  # pyright: ignore[reportPrivateUsage]
        == """[ERROR] Tests run: 4, Failures: 1, Errors: 0, Skipped: 0, Time elapsed: 0.009 s <<< FAILURE! -- in org.apache.commons.compress.compressors.z.ZCompressorInputStreamTest
[ERROR] org.apache.commons.compress.compressors.z.ZCompressorInputStreamTest.testInvalidMaxCodeSize -- Time elapsed: 0.005 s <<< FAILURE!
org.opentest4j.AssertionFailedError: value=-128 ==> Unexpected exception type thrown, expected: <java.lang.IllegalArgumentException> but was: <java.io.IOException>
	at org.junit.jupiter.api.AssertionFailureBuilder.build(AssertionFailureBuilder.java:151)
	at org.junit.jupiter.api.AssertThrows.assertThrows(AssertThrows.java:67)
	at org.junit.jupiter.api.AssertThrows.assertThrows(AssertThrows.java:45)
	at org.junit.jupiter.api.Assertions.assertThrows(Assertions.java:3180)
	at org.apache.commons.compress.compressors.z.ZCompressorInputStreamTest.lambda$testInvalidMaxCodeSize$3(ZCompressorInputStreamTest.java:72)
	at java.base/java.util.stream.Streams$RangeIntSpliterator.forEachRemaining(Streams.java:104)
	at java.base/java.util.stream.IntPipeline$Head.forEach(IntPipeline.java:617)
	at org.apache.commons.compress.compressors.z.ZCompressorInputStreamTest.lambda$testInvalidMaxCodeSize$4(ZCompressorInputStreamTest.java:70)
	at java.base/java.util.Spliterators$ArraySpliterator.forEachRemaining(Spliterators.java:992)
	at java.base/java.util.stream.ReferencePipeline$Head.forEach(ReferencePipeline.java:762)
	at org.apache.commons.compress.compressors.z.ZCompressorInputStreamTest.testInvalidMaxCodeSize(ZCompressorInputStreamTest.java:70)
	at java.base/java.lang.reflect.Method.invoke(Method.java:568)
	at java.base/java.util.ArrayList.forEach(ArrayList.java:1511)
	at java.base/java.util.ArrayList.forEach(ArrayList.java:1511)
Caused by: java.io.IOException: Invalid maxCodeSize in Z header: 0. Must be at least 9.
	at org.apache.commons.compress.compressors.z.ZCompressorInputStream.<init>(ZCompressorInputStream.java:97)
	at org.apache.commons.compress.compressors.z.ZCompressorInputStreamTest.lambda$testInvalidMaxCodeSize$1(ZCompressorInputStreamTest.java:72)
	at org.junit.jupiter.api.AssertThrows.assertThrows(AssertThrows.java:53)
	... 12 more

[INFO] Running org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStreamTest
[INFO] Tests run: 1, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0 s -- in org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStreamTest
[INFO] Running org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStreamTest
[INFO] Tests run: 5, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.002 s -- in org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStreamTest
[INFO] Running org.apache.commons.compress.compressors.deflate.DeflateParametersTest
[INFO] Tests run: 3, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.001 s -- in org.apache.commons.compress.compressors.deflate.DeflateParametersTest
[INFO] Running org.apache.commons.compress.compressors.gzip.SubFieldTest
[INFO] Tests run: 2, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.001 s -- in org.apache.commons.compress.compressors.gzip.SubFieldTest
[INFO] Running org.apache.commons.compress.compressors.gzip.GzipParametersTest
--
[ERROR] Failures: 
[ERROR]   ZCompressorInputStreamTest.testInvalidMaxCodeSize:70->lambda$testInvalidMaxCodeSize$4:70->lambda$testInvalidMaxCodeSize$3:72 value=-128 ==> Unexpected exception type thrown, expected: <java.lang.IllegalArgumentException> but was: <java.io.IOException>
[INFO] 
[ERROR] Tests run: 2905, Failures: 1, Errors: 0, Skipped: 28
[INFO] 
[INFO] ------------------------------------------------------------------------
[INFO] BUILD FAILURE
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  01:47 min
[INFO] Finished at: 2025-06-12T07:10:11Z
[INFO] ------------------------------------------------------------------------
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-surefire-plugin:3.5.2:test (default-test) on project commons-compress: There are test failures.
[ERROR] 
[ERROR] See /src/commons-compress/target/surefire-reports for the individual test results.
[ERROR] See dump files (if any exist) [date].dump, [date]-jvmRun[N].dump and [date].dumpstream.
[ERROR] -> [Help 1]
[ERROR] 
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR] 
[ERROR] For more information about the errors and possible solutions, please read the following articles:
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/MojoFailureException
SLF4J: Failed to load class "org.slf4j.impl.StaticLoggerBinder".
SLF4J: Defaulting to no-operation (NOP) logger implementation
SLF4J: See http://www.slf4j.org/codes.html#StaticLoggerBinder for further details.
/dev/null/not-there doesn't exist or is a directory
"""
    )


def test_extract_build_errors_jvm():
    sbt_build_log = """[info] [launcher] getting org.scala-sbt sbt 1.10.7  (this may take some time)...
[info] [launcher] getting Scala 2.12.20 (for sbt)...
[info] welcome to sbt 1.10.7 (Oracle Corporation Java 17.0.2)
[info] loading settings for project snappy-java-build from plugins.sbt...
[info] loading project definition from /src/snappy-java/project
[info] loading settings for project snappy-java from build.sbt...
[info] set current project to snappy-java (in build file:/src/snappy-java/)
[info] compiling 31 Java sources to /src/snappy-java/target/classes ...
[error] /src/snappy-java/src/main/java/org/xerial/snappy/SnappyInputStream.java:117:56: cannot find symbol
[error]   symbol:   variable INSUFFICIENT_DATA
[error]   location: class org.xerial.snappy.SnappyErrorCode
[error] SnappyErrorCode.INSUFFICIENT_DATA
[error]                                  ^
[error] /src/snappy-java/src/main/java/org/xerial/snappy/SnappyInputStream.java:127:56: cannot find symbol
[error]   symbol:   variable INVALID_MAGIC_HEADER
[error]   location: class org.xerial.snappy.SnappyErrorCode
[error] SnappyErrorCode.INVALID_MAGIC_HEADER
[error]                                     ^
[error] (Compile / compileIncremental) javac returned non-zero exit code
[error] Total time: 1 s, completed Jun 17, 2025, 11:01:30 AM
"""

    assert (
        _extract_build_errors_jvm(sbt_build_log)  # pyright: ignore[reportPrivateUsage]
        == """[error] /src/snappy-java/src/main/java/org/xerial/snappy/SnappyInputStream.java:117:56: cannot find symbol
[error]   symbol:   variable INSUFFICIENT_DATA
[error]   location: class org.xerial.snappy.SnappyErrorCode
[error] SnappyErrorCode.INSUFFICIENT_DATA
[error]                                  ^
[error] /src/snappy-java/src/main/java/org/xerial/snappy/SnappyInputStream.java:127:56: cannot find symbol
[error]   symbol:   variable INVALID_MAGIC_HEADER
[error]   location: class org.xerial.snappy.SnappyErrorCode
[error] SnappyErrorCode.INVALID_MAGIC_HEADER
[error]                                     ^
[error] (Compile / compileIncremental) javac returned non-zero exit code
[error] Total time: 1 s, completed Jun 17, 2025, 11:01:30 AM
"""
    )

    maven_build_log = """[INFO] Apache Tika Optimaize langdetect ................... SKIPPED
[INFO] Apache Tika pipes .................................. SKIPPED
[INFO] Apache Tika emitters ............................... SKIPPED
[INFO] Apache Tika filesystem emitter ..................... SKIPPED
[INFO] Apache Tika Async CLI .............................. SKIPPED
[INFO] Apache Tika application ............................ SKIPPED
[INFO] ------------------------------------------------------------------------
[INFO] BUILD FAILURE
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  16.442 s
[INFO] Finished at: 2025-06-15T17:34:11Z
[INFO] ------------------------------------------------------------------------
[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.14.0:compile (default-compile) on project tika-core: Compilation failure
[ERROR] /src/project-parent/tika/tika-core/src/main/java/org/apache/tika/parser/external/ExternalParser.java:[433,5] illegal start of expression
[ERROR] 
[ERROR] -> [Help 1]
[ERROR] 
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR] 
[ERROR] For more information about the errors and possible solutions, please read the following articles:
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/MojoFailureException
[ERROR] 
[ERROR] After correcting the problems, you can resume the build with the command
[ERROR]   mvn <args> -rf :tika-core
subprocess command returned a non-zero exit status: 1
"""
    assert (
        _extract_build_errors_jvm(maven_build_log)  # pyright: ignore[reportPrivateUsage]
        == """[ERROR] Failed to execute goal org.apache.maven.plugins:maven-compiler-plugin:3.14.0:compile (default-compile) on project tika-core: Compilation failure
[ERROR] /src/project-parent/tika/tika-core/src/main/java/org/apache/tika/parser/external/ExternalParser.java:[433,5] illegal start of expression
[ERROR] 
[ERROR] -> [Help 1]
[ERROR] 
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch.
[ERROR] Re-run Maven using the -X switch to enable full debug logging.
[ERROR] 
[ERROR] For more information about the errors and possible solutions, please read the following articles:
[ERROR] [Help 1] http://cwiki.apache.org/confluence/display/MAVEN/MojoFailureException
[ERROR] 
[ERROR] After correcting the problems, you can resume the build with the command
[ERROR]   mvn <args> -rf :tika-core
subprocess command returned a non-zero exit status: 1
"""
    )

    invalid_build_log = "This is an invalid build log"

    assert (
        _extract_build_errors_jvm(invalid_build_log) == "This is an invalid build log"
    )  # pyright: ignore[reportPrivateUsage]


def test_extract_build_error_c():
    build_error_log = """/work/ccache/clang -c -O0 -g -O0 -g -I src/core -I src/event -I src/event/modules -I src/os/unix -I objs -I src/stream \
	-o objs/src/stream/ngx_stream_upstream_zone_module.o \
	src/stream/ngx_stream_upstream_zone_module.c
/work/ccache/clang -c -O0 -g -O0 -g -I src/core -I src/event -I src/event/modules -I src/os/unix -I objs \
	-o objs/ngx_modules.o \
	objs/ngx_modules.c
sed -e "s|%%PREFIX%%|/usr/local/nginx|" \
	-e "s|%%PID_PATH%%|/out/logs/nginx.pid|" \
	-e "s|%%CONF_PATH%%|/out/conf/nginx.conf|" \
	-e "s|%%ERROR_LOG_PATH%%|/usr/local/nginx/logs/error.log|" \
	< docs/man/nginx.8 > objs/nginx.8
src/core/ngx_cycle.c:1689:1: error: function definition is not allowed here
 1689 | {
      | ^
src/core/ngx_cycle.c:1700:2: error: expected '}'
 1700 | }
      |  ^
src/core/ngx_cycle.c:1658:1: note: to match this '{'
 1658 | {
      | ^
2 errors generated.
make: *** [objs/Makefile:659: objs/src/core/ngx_cycle.o] Error 1
"""

    assert (
        _extract_build_errors_c(build_error_log)
        == """src/core/ngx_cycle.c:1689:1: error: function definition is not allowed here
 1689 | {
      | ^
src/core/ngx_cycle.c:1700:2: error: expected '}'
 1700 | }
      |  ^
src/core/ngx_cycle.c:1658:1: note: to match this '{'
 1658 | {
      | ^
2 errors generated.
make: *** [objs/Makefile:659: objs/src/core/ngx_cycle.o] Error 1
"""
    )

    assert (
        _extract_build_errors_c("This is an invalid build log")
        == "This is an invalid build log"
    )
