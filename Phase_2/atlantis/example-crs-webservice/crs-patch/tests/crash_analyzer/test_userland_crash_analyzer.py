from pathlib import Path

import pytest

from crete.commons.crash_analysis.functions.userland_crash import analyze_userland_crash
from crete.framework.fault_localizer.models import FaultLocation
from crete.framework.fault_localizer.services.stacktrace import (
    fault_locations_from_crash_stacks,
)

pov_output = b"""INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3666767511
INFO: Loaded 1 modules   (80 inline 8-bit counters): 80 [0x5577fdbc2d78, 0x5577fdbc2dc8),
INFO: Loaded 1 PC tables (80 PCs): 80 [0x5577fdbc2dc8,0x5577fdbc32c8),
/out/pov_harness: Running 1 inputs 100 time(s) each.
Running: /work/tmp_blob
=================================================================
==38==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50400000253b at pc 0x5577fd8d9be5 bp 0x7ffd977357d0 sp 0x7ffd977357c8
WRITE of size 1 at 0x50400000253b thread T0
    #0 0x5577fd8d9be4 in ngx_sprintf_str /src/harnesses/bld/src/core/ngx_string.c:581:24
    #1 0x5577fd8d789d in ngx_vslprintf /src/harnesses/bld/src/core/ngx_string.c
    #2 0x5577fd8d66f5 in ngx_sprintf /src/harnesses/bld/src/core/ngx_string.c:129:9
    #3 0x5577fd977d59 in ngx_http_set_browser_cookie /src/harnesses/bld/src/http/ngx_http_core_module.c:5289:37
    #4 0x5577fda18415 in ngx_http_static_handler /src/harnesses/bld/src/http/modules/ngx_http_static_module.c:243:9
    #5 0x5577fd971b68 in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #6 0x5577fd96f169 in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #7 0x5577fd96f169 in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #8 0x5577fd97658a in ngx_http_internal_redirect /src/harnesses/bld/src/http/ngx_http_core_module.c:2547:5
    #9 0x5577fda24a43 in ngx_http_index_handler /src/harnesses/bld/src/http/modules/ngx_http_index_module.c
    #10 0x5577fd971b68 in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #11 0x5577fd96f169 in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #12 0x5577fd96f169 in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #13 0x5577fd98feae in ngx_http_process_request /src/harnesses/bld/src/http/ngx_http_request.c:2133:5
    #14 0x5577fd99431b in ngx_http_process_request_headers /src/harnesses/bld/src/http/ngx_http_request.c:1529:13
    #15 0x5577fd929bdc in ngx_event_process_posted /src/harnesses/bld/src/event/ngx_event_posted.c:34:9
    #16 0x5577fd8c4a37 in LLVMFuzzerTestOneInput /src/harnesses/bld/src/harnesses/pov_harness.cc:323:5
    #17 0x5577fd776780 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #18 0x5577fd760f14 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #19 0x5577fd7669aa in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #20 0x5577fd792da2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #21 0x7f8cd83df082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)
    #22 0x5577fd7579ed in _start (/out/pov_harness+0xb59ed)

0x50400000253b is located 0 bytes after 43-byte region [0x504000002510,0x50400000253b)
allocated by thread T0 here:
    #0 0x5577fd884d1e in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
    #1 0x5577fd9355f4 in ngx_alloc /src/harnesses/bld/src/os/unix/ngx_alloc.c:22:9
    #2 0x5577fd8cc7eb in ngx_palloc_large /src/harnesses/bld/src/core/ngx_palloc.c:220:9
    #3 0x5577fd977c83 in ngx_http_set_browser_cookie /src/harnesses/bld/src/http/ngx_http_core_module.c:5281:34
    #4 0x5577fda18415 in ngx_http_static_handler /src/harnesses/bld/src/http/modules/ngx_http_static_module.c:243:9
    #5 0x5577fd971b68 in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #6 0x5577fd96f169 in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #7 0x5577fd96f169 in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #8 0x5577fd97658a in ngx_http_internal_redirect /src/harnesses/bld/src/http/ngx_http_core_module.c:2547:5
    #9 0x5577fda24a43 in ngx_http_index_handler /src/harnesses/bld/src/http/modules/ngx_http_index_module.c
    #10 0x5577fd971b68 in ngx_http_core_content_phase /src/harnesses/bld/src/http/ngx_http_core_module.c:1268:10
    #11 0x5577fd96f169 in ngx_http_core_run_phases /src/harnesses/bld/src/http/ngx_http_core_module.c:875:14
    #12 0x5577fd96f169 in ngx_http_handler /src/harnesses/bld/src/http/ngx_http_core_module.c:858:5
    #13 0x5577fd98feae in ngx_http_process_request /src/harnesses/bld/src/http/ngx_http_request.c:2133:5
    #14 0x5577fd99431b in ngx_http_process_request_headers /src/harnesses/bld/src/http/ngx_http_request.c:1529:13
    #15 0x5577fd929bdc in ngx_event_process_posted /src/harnesses/bld/src/event/ngx_event_posted.c:34:9
    #16 0x5577fd8c4a37 in LLVMFuzzerTestOneInput /src/harnesses/bld/src/harnesses/pov_harness.cc:323:5
    #17 0x5577fd776780 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #18 0x5577fd760f14 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #19 0x5577fd7669aa in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #20 0x5577fd792da2 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #21 0x7f8cd83df082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harnesses/bld/src/core/ngx_string.c:581:24 in ngx_sprintf_str
Shadow bytes around the buggy address:
  0x504000002280: fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa
  0x504000002300: fa fa fd fd fd fd fd fa fa fa fd fd fd fd fd fa
  0x504000002380: fa fa 00 00 00 00 00 04 fa fa 00 00 00 00 00 00
  0x504000002400: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 06
  0x504000002480: fa fa 00 00 00 00 00 00 fa fa 00 00 00 00 00 03
=>0x504000002500: fa fa 00 00 00 00 00[03]fa fa fa fa fa fa fa fa
  0x504000002580: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000002600: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000002680: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000002700: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x504000002780: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
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
==38==ABORTING
libfuzzer exit=1
"""


@pytest.mark.slow
def test_stacktrace_fault_localizer(
    detection_c_asc_nginx_cpv_4: tuple[Path, Path],
):
    source_directory, _ = detection_c_asc_nginx_cpv_4

    crash_stacks = analyze_userland_crash(source_directory, pov_output).crash_stacks
    assert fault_locations_from_crash_stacks(crash_stacks)[:14] == [
        FaultLocation(
            file=source_directory / "src/core/ngx_string.c",
            function_name="ngx_sprintf_str",
            line_range=(579, 580),
        ),
        FaultLocation(
            file=source_directory / "src/core/ngx_string.c",
            function_name="ngx_sprintf",
            line_range=(127, 128),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_set_browser_cookie",
            line_range=(5287, 5288),
        ),
        FaultLocation(
            file=source_directory / "src/http/modules/ngx_http_static_module.c",
            function_name="ngx_http_static_handler",
            line_range=(241, 242),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_core_content_phase",
            line_range=(1266, 1267),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_core_run_phases",
            line_range=(873, 874),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_handler",
            line_range=(856, 857),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_internal_redirect",
            line_range=(2545, 2546),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_core_content_phase",
            line_range=(1266, 1267),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_core_run_phases",
            line_range=(873, 874),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_core_module.c",
            function_name="ngx_http_handler",
            line_range=(856, 857),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_request.c",
            function_name="ngx_http_process_request",
            line_range=(2131, 2132),
        ),
        FaultLocation(
            file=source_directory / "src/http/ngx_http_request.c",
            function_name="ngx_http_process_request_headers",
            line_range=(1527, 1528),
        ),
        FaultLocation(
            file=source_directory / "src/event/ngx_event_posted.c",
            function_name="ngx_event_process_posted",
            line_range=(32, 33),
        ),
    ]


# TODO: Add new unit test for UndefinedBehaviorSanitizer (UBSan)
'''
def test_cp_user_dav1d_cpv_1(detection_dav1d_cpv_0: tuple[Path, Path]):
    pov_output = b"""INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2291703157
/out/dav1d_fuzzer: Running 1 inputs 1 time(s) each.
Running: /work/tmp_blob
../src/samples/src/decode.c:2811:70: runtime error: signed integer overflow: 2081996800 + 70246400 cannot be represented in type 'int'
    #0 0x55682ef3e143 in dav1d_decode_frame_init /work/../src/samples/src/decode.c:2811:70
    #1 0x55682eef7f3d in dav1d_worker_task /work/../src/samples/src/thread_task.c:696:23
    #2 0x55682ee53f78 in asan_thread_start(void*) /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:239:28
    #3 0x7fa8e75c0608 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x8608) (BuildId: 9a65bb469e45a1c6fbcffae5b82a2fd7a69eb479)
    #4 0x7fa8e74a2352 in __clone (/lib/x86_64-linux-gnu/libc.so.6+0x11f352) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../src/samples/src/decode.c:2811:70 
../src/samples/src/decode.c:2807:54: runtime error: signed integer overflow: 16891200 * 128 cannot be represented in type 'int'
    #0 0x55682ef3e6ea in dav1d_decode_frame_init /work/../src/samples/src/decode.c:2807:54
    #1 0x55682eef7f3d in dav1d_worker_task /work/../src/samples/src/thread_task.c:696:23
    #2 0x55682ee53f78 in asan_thread_start(void*) /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:239:28
    #3 0x7fa8e75c0608 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x8608) (BuildId: 9a65bb469e45a1c6fbcffae5b82a2fd7a69eb479)
    #4 0x7fa8e74a2352 in __clone (/lib/x86_64-linux-gnu/libc.so.6+0x11f352) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ../src/samples/src/decode.c:2807:54 
AddressSanitizer:DEADLYSIGNAL
=================================================================
AddressSanitizer:DEADLYSIGNAL
==36==ERROR: AddressSanitizer: SEGV on unknown address (pc 0x55682f046a80 bp 0x7fa8e20a4320 sp 0x7fa8e20a4160 T2)
==36==The signal is caused by a READ memory access.
==36==Hint: this fault was caused by a dereference of a high value address (see register values below).  Disassemble the provided pc to learn which register was used.
    #0 0x55682f046a80 in decode_coefs /work/../src/samples/src/recon_tmpl.c:689:15
    #1 0x55682f03ac99 in dav1d_read_coef_blocks_8bpc /work/../src/samples/src/recon_tmpl.c:885:29
    #2 0x55682ef77bf7 in decode_b /work/../src/samples/src/decode.c:1212:13
    #3 0x55682ef325be in decode_sb /work/../src/samples/src/decode.c:2168:17
    #4 0x55682ef2c3e5 in dav1d_decode_tile_sbrow /work/../src/samples/src/decode.c:2716:13
    #5 0x55682eef800d in dav1d_worker_task /work/../src/samples/src/thread_task.c:761:33
    #6 0x55682ee53f78 in asan_thread_start(void*) /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:239:28
    #7 0x7fa8e75c0608 in start_thread (/lib/x86_64-linux-gnu/libpthread.so.0+0x8608) (BuildId: 9a65bb469e45a1c6fbcffae5b82a2fd7a69eb479)
    #8 0x7fa8e74a2352 in __clone (/lib/x86_64-linux-gnu/libc.so.6+0x11f352) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV /work/../src/samples/src/recon_tmpl.c:689:15 in decode_coefs
Thread T2 (dav1d-worker) created by T0 here:
    #0 0x55682ee3bfc1 in pthread_create /src/llvm-project/compiler-rt/lib/asan/asan_interceptors.cpp:250:3
    #1 0x55682ed2115f in dav1d_open /work/../src/samples/src/lib.c:280:17
    #2 0x55682ee95c8b in LLVMFuzzerTestOneInput /work/../src/samples/tests/libfuzzer/dav1d_fuzzer.c:54:11
    #3 0x55682f2d87c0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #4 0x55682f2c3a35 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #5 0x55682f2c94cf in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #6 0x55682f2f4772 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #7 0x7fa8e73a7082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0702430aef5fa3dda43986563e9ffcc47efbd75e)

==36==ABORTING
libfuzzer exit=1"""
    context, _ = AIxCCContextBuilder(
        *detection_dav1d_cpv_0,
        evaluator=DummyEvaluator(),
        environment=MockEnvironment(*detection_dav1d_cpv_0),
    ).build(
        previous_action=HeadAction(),
    )

    crash_stacks = analyze_userland_crash(context, pov_output).crash_stacks
    assert fault_locations_from_crash_stacks(crash_stacks) == [
        FaultLocation(
            file=context["pool"].source_directory / "src/decode.c",
            function_name="dav1d_decode_frame_init",
            line_range=(2809, 2810),
        ),
        FaultLocation(
            file=context["pool"].source_directory / "src/thread_task.c",
            function_name="dav1d_worker_task",
            line_range=(694, 695),
        ),
    ]
'''
