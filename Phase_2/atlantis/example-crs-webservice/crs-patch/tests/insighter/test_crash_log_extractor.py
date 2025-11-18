from unittest.mock import Mock

import pytest
from crete.commons.logging.hooks import use_logger
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.services.crash_log_extractor import CrashLogSummarizer
from python_llm.api.actors import LlmApiManager


@pytest.fixture
def context():
    return InsighterContext(
        memory=Mock(),
        pool=Mock(),
        crash_log_analyzer=Mock(),
        call_trace_snapshot=Mock(),
        logger=use_logger("test"),
        logging_prefix="test",
        language_parser=Mock(),
        lsp_client=Mock(),
        sanitizer_name="address",
    )


@pytest.mark.vcr()
def test_crash_log_extractor(context: InsighterContext):
    crash_log = """+ FUZZER=http_request_fuzzer
+ shift
+ '[' '!' -v TESTCASE ']'
+ TESTCASE=/testcase
+ '[' '!' -f /testcase ']'
+ export RUN_FUZZER_MODE=interactive
+ RUN_FUZZER_MODE=interactive
+ export FUZZING_ENGINE=libfuzzer
+ FUZZING_ENGINE=libfuzzer
+ export SKIP_SEED_CORPUS=1
+ SKIP_SEED_CORPUS=1
+ run_fuzzer http_request_fuzzer -runs=100 /testcase
vm.mmap_rnd_bits = 28
/out/http_request_fuzzer -rss_limit_mb=2560 -timeout=25 -runs=100 /testcase -dict=http_request_fuzzer.dict < /dev/null
INFO: found LLVMFuzzerCustomMutator (0x55b8676a1df0). Disabling -len_control by default.
Dictionary: 141 entries
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 4254896542
INFO: Loaded 1 modules   (24033 inline 8-bit counters): 24033 [0x55b867c040e8, 0x55b867c09ec9),
INFO: Loaded 1 PC tables (24033 PCs): 24033 [0x55b867c09ed0,0x55b867c67ce0),
/out/http_request_fuzzer: Running 1 inputs 100 time(s) each.
Running: /testcase
=================================================================
[1m[31m==14==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50200000b668 at pc 0x55b8678f0c44 bp 0x7ffefb8e97a0 sp 0x7ffefb8e9798
[1m[0m[1m[34mREAD of size 8 at 0x50200000b668 thread T0[1m[0m
SCARINESS: 33 (8-byte-read-heap-buffer-overflow-far-from-bounds)
    #0 0x55b8678f0c43 in ngx_http_process_custom_features /src/nginx/src/http/ngx_http_request.c:2006:5
    #1 0x55b8678fc977 in ngx_http_process_request_headers /src/nginx/src/http/ngx_http_request.c:1507:23
    #2 0x55b8678fb93b in ngx_http_process_request_line /src/nginx/src/http/ngx_http_request.c:1202:13
    #3 0x55b8676a2b10 in TestOneProtoInput /src/nginx/src/fuzz/http_request_fuzzer.cc:315:3
    #4 0x55b8676a2b10 in LLVMFuzzerTestOneInput /src/nginx/src/fuzz/http_request_fuzzer.cc:246:1
    #5 0x55b867556250 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #6 0x55b8675414c5 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #7 0x55b867546f5f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #8 0x55b867572202 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #9 0x7f295b2d8082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #10 0x55b8675396ad in _start (/out/http_request_fuzzer+0x1966ad)

DEDUP_TOKEN: ngx_http_process_custom_features--ngx_http_process_request_headers--ngx_http_process_request_line
[1m[32m0x50200000b668 is located 48 bytes after 8-byte region [0x50200000b630,0x50200000b638)
[1m[0m[1m[35mallocated by thread T0 here:[1m[0m
    #0 0x55b86766201f in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3
    #1 0x55b8678b42ef in ngx_alloc /src/nginx/src/os/unix/ngx_alloc.c:22:9
    #2 0x55b8678366a1 in ngx_palloc_large /src/nginx/src/core/ngx_palloc.c:220:9
    #3 0x55b867837097 in ngx_palloc /src/nginx/src/core/ngx_palloc.c:131:12
    #4 0x55b867837097 in ngx_pcalloc /src/nginx/src/core/ngx_palloc.c:302:9
    #5 0x55b8678f0afd in ngx_http_process_custom_features /src/nginx/src/http/ngx_http_request.c:1987:34
    #6 0x55b8678fc977 in ngx_http_process_request_headers /src/nginx/src/http/ngx_http_request.c:1507:23
    #7 0x55b8678fb93b in ngx_http_process_request_line /src/nginx/src/http/ngx_http_request.c:1202:13
    #8 0x55b8676a2b10 in TestOneProtoInput /src/nginx/src/fuzz/http_request_fuzzer.cc:315:3
    #9 0x55b8676a2b10 in LLVMFuzzerTestOneInput /src/nginx/src/fuzz/http_request_fuzzer.cc:246:1
    #10 0x55b867556250 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #11 0x55b8675414c5 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #12 0x55b867546f5f in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #13 0x55b867572202 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #14 0x7f295b2d8082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

DEDUP_TOKEN: __interceptor_malloc--ngx_alloc--ngx_palloc_large
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/nginx/src/http/ngx_http_request.c:2006:5 in ngx_http_process_custom_features
Shadow bytes around the buggy address:
  0x50200000b380: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m03[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m02[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m06[1m[0m
  0x50200000b400: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m
  0x50200000b480: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m
  0x50200000b500: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m
  0x50200000b580: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m07[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m04[1m[0m [1m[31mfa[1m[0m
=>0x50200000b600: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[0m01[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[0m00[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m[[1m[31mfa[1m[0m][1m[31mfa[1m[0m [1m[31mfa[1m[0m
  0x50200000b680: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m
  0x50200000b700: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m
  0x50200000b780: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m
  0x50200000b800: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m
  0x50200000b880: [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m [1m[31mfa[1m[0m
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           [1m[0m00[1m[0m
  Partially addressable: [1m[0m01[1m[0m [1m[0m02[1m[0m [1m[0m03[1m[0m [1m[0m04[1m[0m [1m[0m05[1m[0m [1m[0m06[1m[0m [1m[0m07[1m[0m
  Heap left redzone:       [1m[31mfa[1m[0m
  Freed heap region:       [1m[35mfd[1m[0m
  Stack left redzone:      [1m[31mf1[1m[0m
  Stack mid redzone:       [1m[31mf2[1m[0m
  Stack right redzone:     [1m[31mf3[1m[0m
  Stack after return:      [1m[35mf5[1m[0m
  Stack use after scope:   [1m[35mf8[1m[0m
  Global redzone:          [1m[31mf9[1m[0m
  Global init order:       [1m[36mf6[1m[0m
  Poisoned by user:        [1m[34mf7[1m[0m
  Container overflow:      [1m[34mfc[1m[0m
  Array cookie:            [1m[31mac[1m[0m
  Intra object redzone:    [1m[33mbb[1m[0m
  ASan internal:           [1m[33mfe[1m[0m
  Left alloca redzone:     [1m[34mca[1m[0m
  Right alloca redzone:    [1m[34mcb[1m[0m
==14==ABORTING
"""
    crash_log_extractor = CrashLogSummarizer(
        LlmApiManager.from_environment(model="gpt-4o-mini"),
        crash_log,
    )
    result = crash_log_extractor.create(context, Mock())
    assert result is not None, "Result is None"
