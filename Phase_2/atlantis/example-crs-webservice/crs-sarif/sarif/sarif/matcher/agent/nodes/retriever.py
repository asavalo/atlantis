import inspect
import base64
import re
from loguru import logger
import json

import langchain
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

langchain.debug = True

from sarif.sarif.matcher.agent.state import SarifMatchingState
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.sarif.matcher.agent.state import SarifMatchingAction
from sarif.sarif.matcher.agent.retrievers.by_lineno_retriever import ByLinenoRetriever


class RetrieverNode:
    def __call__(self, state: SarifMatchingState) -> SarifMatchingState:
        # logger.info(json.dumps(state.model_dump(), indent=4))
        if state.retrieve_query is None:
            return {"next_action": SarifMatchingAction.MATCHING}

        match state.retrieve_query.split(":")[0]:
            case "BY_LINENO":
                retriever = ByLinenoRetriever(state.src_dir)
                retrieved = retriever(state.retrieve_query)
                if retrieved is None:
                    return {"next_action": SarifMatchingAction.MATCHING}
            case _:
                return {"next_action": SarifMatchingAction.MATCHING}

        return {
            "next_action": SarifMatchingAction.MATCHING,
            "retrieved": retrieved,
        }


if __name__ == "__main__":
    sarif = AIxCCSarif.model_validate(
        {
            "runs": [
                {
                    "artifacts": [{"location": {"index": 0, "uri": "pngrutil.c"}}],
                    "automationDetails": {"id": "/"},
                    "conversion": {
                        "tool": {"driver": {"name": "GitHub Code Scanning"}}
                    },
                    "results": [
                        {
                            "correlationGuid": "9d13d264-74f2-48cc-a3b9-d45a8221b3e1",
                            "level": "error",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "index": 0,
                                            "uri": "pngrutil.c",
                                        },
                                        "region": {
                                            "endLine": 1447,
                                            "startColumn": 1,
                                            "startLine": 1421,
                                        },
                                    }
                                }
                            ],
                            "message": {"text": "Associated risk: CWE-121"},
                            "partialFingerprints": {
                                "primaryLocationLineHash": "22ac9f8e7c3a3bd8:8"
                            },
                            "properties": {
                                "github/alertNumber": 2,
                                "github/alertUrl": "https://api.github.com/repos/aixcc-finals/example-libpng/code-scanning/alerts/2",
                            },
                            "rule": {"id": "CWE-121", "index": 0},
                            "ruleId": "CWE-121",
                        }
                    ],
                    "tool": {
                        "driver": {
                            "name": "CodeScan++",
                            "rules": [
                                {
                                    "defaultConfiguration": {"level": "warning"},
                                    "fullDescription": {
                                        "text": "vulnerable to #CWE-121"
                                    },
                                    "helpUri": "https://example.com/help/png_handle_iCCP",
                                    "id": "CWE-121",
                                    "properties": {},
                                    "shortDescription": {"text": "CWE #CWE-121"},
                                }
                            ],
                            "version": "1.0.0",
                        }
                    },
                    "versionControlProvenance": [
                        {
                            "branch": "refs/heads/challenges/full-scan",
                            "repositoryUri": "https://github.com/aixcc-finals/example-libpng",
                            "revisionId": "fdacd5a1dcff42175117d674b0fda9f8a005ae88",
                        }
                    ],
                }
            ],
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
        }
    )

    testcase = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgEAIAAACsiDHgAAAABHNCSVRnQU1BAAGGoDHoll9pQ0NQdFJOU////////569S9jEYlOYYsAWlqG1o2UjoXY8XB0iIEygVJTCutJSWgodHWUQGA43tzkHok40OnFkOmYMMWbMRONzD7a5qfH9f6A2WVC6Z0lGdMvljt73/3/////////////////////////////////////////////////////////////////////////////////////////////vO/H7/5z4rwO4WAuSwOfkADlNFqIUNg8JfE32kjpSQEpKHgZ1dXeArVvTwNiYCxw7NgUAAJbnSLAAAAAEZ0FNQQABhqAx6JZfAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAENvcHlyaWdodACpILYgnxaPEhfhWYu/dyxEWQv4cfcc4e+kC1fK//7r9B+bDPkeC/hx9xzh76QLV8r//uv0H5sM+R76omEaAAAgAElFTkSuQmCC"
    crash_log = inspect.cleandoc(
        """
        INFO: Running with entropic power schedule (0xFF, 100).
        INFO: Seed: 11513192
        INFO: Loaded 1 modules   (5641 inline 8-bit counters): 5641 [0x5620ec400928, 0x5620ec401f31),
        INFO: Loaded 1 PC tables (5641 PCs): 5641 [0x5620ec401f38,0x5620ec417fc8),
        /out/libpng_read_fuzzer: Running 1 inputs 100 time(s) each.
        Running: /testcase
        =================================================================
        ==18==ERROR: AddressSanitizer: dynamic-stack-buffer-overflow on address 0x7fff8d4e98b2 at pc 0x5620ec34aa9b bp 0x7fff8d4e9830 sp 0x7fff8d4e9828
        READ of size 2 at 0x7fff8d4e98b2 thread T0
        SCARINESS: 29 (2-byte-read-dynamic-stack-buffer-overflow)
            #0 0x5620ec34aa9a in OSS_FUZZ_png_handle_iCCP /src/libpng/pngrutil.c:1447:10
            #1 0x5620ec31edcd in OSS_FUZZ_png_read_info /src/libpng/pngread.c:229:10
            #2 0x5620ec2724ae in LLVMFuzzerTestOneInput /src/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc:156:3
            #3 0x5620ec290520 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
            #4 0x5620ec27b795 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
            #5 0x5620ec28122f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
            #6 0x5620ec2ac4d2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
            #7 0x7f59d7162082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
            #8 0x5620ec19983d in _start (/out/libpng_read_fuzzer+0x6c83d)

        DEDUP_TOKEN: OSS_FUZZ_png_handle_iCCP--OSS_FUZZ_png_read_info--LLVMFuzzerTestOneInput
        Address 0x7fff8d4e98b2 is located in stack of thread T0
        SUMMARY: AddressSanitizer: dynamic-stack-buffer-overflow /src/libpng/pngrutil.c:1447:10 in OSS_FUZZ_png_handle_iCCP
        Shadow bytes around the buggy address:
        0x7fff8d4e9600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9680: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9700: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9780: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9800: 00 00 00 00 00 00 00 00 ca ca ca ca 00 00 00 00
        =>0x7fff8d4e9880: 00 00 00 00 00 00[02]cb cb cb cb cb 00 00 00 00
        0x7fff8d4e9900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        0x7fff8d4e9a80: 00 00 00 00 00 00 00 00 f1 f1 f1 f1 00 00 00 f2
        0x7fff8d4e9b00: f2 f2 f2 f2 00 00 00 00 00 f2 f2 f2 f2 f2 f8 f2
        Shadow byte legend (one shadow byte represents 8 application bytes):
        Addressable:           00
        Partially addressable: 01 02 03 04 05 06 07
        Heap left redzone:       fa
        Freed heap region:       fd
        Stack left redzone:      f1
        Stack mid redzone:       f2
        Stack right redzone:     f3
        Stack after return:      f5
        Stack use after scope:   f8
        Global redzone:          f9
        Global init order:       f6
        Poisoned by user:        f7
        Container overflow:      fc
        Array cookie:            ac
        Intra object redzone:    bb
        ASan internal:           fe
        Left alloca redzone:     ca
        Right alloca redzone:    cb
        ==18==ABORTING
    """
    )

    # patch_diff = inspect.cleandoc(
    #     """
    # diff --git a/pngrutil.c b/pngrutil.c
    # index 01e08bfe7..7c609b4b4 100644
    # --- a/pngrutil.c
    # +++ b/pngrutil.c
    # @@ -1419,13 +1419,12 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    #     if ((png_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_INTENT) == 0)
    #     {
    #     uInt read_length, keyword_length;
    # -      uInt max_keyword_wbytes = 41;
    # -      wpng_byte keyword[max_keyword_wbytes];
    # +      char keyword[81];

    #     /* Find the keyword; the keyword plus separator and compression method
    # -       * bytes can be at most 41 wide characters long.
    # +       * bytes can be at most 81 characters long.
    #         */
    # -      read_length = sizeof(keyword); /* maximum */
    # +      read_length = 81; /* maximum */
    #     if (read_length > length)
    #         read_length = (uInt)length;

    # @@ -1443,12 +1442,12 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    #     }

    #     keyword_length = 0;
    # -      while (keyword_length < (read_length-1) && keyword_length < read_length &&
    # +      while (keyword_length < 80 && keyword_length < read_length &&
    #         keyword[keyword_length] != 0)
    #         ++keyword_length;

    #     /* TODO: make the keyword checking common */
    # -      if (keyword_length >= 1 && keyword_length <= (read_length-2))
    # +      if (keyword_length >= 1 && keyword_length <= 79)
    #     {
    #         /* We only understand '0' compression - deflate - so if we get a
    #         * different value we can't safely decode the chunk.
    # @@ -1477,13 +1476,13 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    #                 png_uint_32 profile_length = png_get_uint_32(profile_header);

    #                 if (png_icc_check_length(png_ptr, &png_ptr->colorspace,
    # -                      (char*)keyword, profile_length) != 0)
    # +                      keyword, profile_length) != 0)
    #                 {
    #                     /* The length is apparently ok, so we can check the 132
    #                     * byte header.
    #                     */
    #                     if (png_icc_check_header(png_ptr, &png_ptr->colorspace,
    # -                         (char*)keyword, profile_length, profile_header,
    # +                         keyword, profile_length, profile_header,
    #                         png_ptr->color_type) != 0)
    #                     {
    #                         /* Now read the tag table; a variable size buffer is
    # @@ -1513,7 +1512,7 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    #                             if (size == 0)
    #                             {
    #                             if (png_icc_check_tag_table(png_ptr,
    # -                                  &png_ptr->colorspace, (char*)keyword, profile_length,
    # +                                  &png_ptr->colorspace, keyword, profile_length,
    #                                 profile) != 0)
    #                             {
    #                                 /* The profile has been validated for basic
    # """
    # )

    #     patch_diff = inspect.cleandoc(
    #         """
    # diff --git a/pngrutil.c b/pngrutil.c
    # index 01e08bfe7..4b30eee22 100644
    # --- a/pngrutil.c
    # +++ b/pngrutil.c
    # @@ -1443,7 +1443,7 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    #        }

    #        keyword_length = 0;
    # -      while (keyword_length < (read_length-1) && keyword_length < read_length &&
    # +      while (read_length > 1 && keyword_length < read_length - 1 &&
    #           keyword[keyword_length] != 0)
    #           ++keyword_length;"""
    #     )
    patch_diff = None

    from langchain_openai import ChatOpenAI

    model = "claude-3-7-sonnet-20250219"
    llm = ChatOpenAI(model=model)
    state = SarifMatchingState(
        sarif=sarif,
        testcase=testcase,
        crash_log=crash_log,
        patch_diff=patch_diff,
        src_dir="/home/kyuheon/example-libpng",
        retrieve_query="BY_LINENO:pngrutil.c:1421-1447",
    )
    retriever = RetrieverNode()
    print(retriever(state)["retrieved"])
