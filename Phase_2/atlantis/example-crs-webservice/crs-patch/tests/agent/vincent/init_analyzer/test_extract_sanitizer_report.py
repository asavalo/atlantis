from pathlib import Path

import pytest
from crete.atoms.action import HeadAction
from crete.framework.agent.services.vincent.functions import extract_sanitizer_report
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crete.framework.environment.exceptions import ChallengePoVFoundError

undefined_bahavior_log = """+ FUZZER=sndfile_fuzzer
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
+ run_fuzzer sndfile_fuzzer -runs=100 /testcase
vm.mmap_rnd_bits = 28
/out/sndfile_fuzzer -rss_limit_mb=2560 -timeout=25 -runs=100 /testcase -close_fd_mask=3 < /dev/null
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 445322936
INFO: Loaded 1 modules   (10917 inline 8-bit counters): 10917 [0x55bcd8efa300, 0x55bcd8efcda5), 
INFO: Loaded 1 PC tables (10917 PCs): 10917 [0x55bcd8efcda8,0x55bcd8f277f8), 
/out/sndfile_fuzzer: Running 1 inputs 100 time(s) each.
Running: /testcase
==18==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x55bcaa07e6ec (pc 0x7fbeba6e19a9 bp 0x7fffc1a6d1e0 sp 0x7fffc1a6d1a8 T18)
==18==The signal is caused by a WRITE memory access.
    #0 0x7fbeba6e19a9  (/lib/x86_64-linux-gnu/libc.so.6+0x1689a9) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #1 0x55bcd8df84cf in memcpy /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34:10
    #2 0x55bcd8df84cf in vfread(void*, long, void*) /src/libsndfile/ossfuzz/sndfile_fuzzer.cc:54:3
    #3 0x55bcd8e3edb2 in psf_fread /src/libsndfile/src/file_io.c:311:10
    #4 0x55bcd8e352e6 in header_read /src/libsndfile/src/common.c:857:12
    #5 0x55bcd8e34e47 in psf_binheader_readf /src/libsndfile/src/common.c
    #6 0x55bcd8e09c4e in caf_read_header /src/libsndfile/src/caf.c:395:3
    #7 0x55bcd8e09c4e in caf_open /src/libsndfile/src/caf.c:127:17
    #8 0x55bcd8df9295 in psf_open_file /src/libsndfile/src/sndfile.c:3180:13
    #9 0x55bcd8df8329 in LLVMFuzzerTestOneInput /src/libsndfile/ossfuzz/sndfile_fuzzer.cc:99:13
    #10 0x55bcd8d5a8a0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #11 0x55bcd8d45b15 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #12 0x55bcd8d4b5af in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #13 0x55bcd8d76852 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #14 0x7fbeba59d082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #15 0x55bcd8d3dcfd in _start (/out/sndfile_fuzzer+0x62cfd)

DEDUP_TOKEN: memcpy--vfread(void*, long, void*)
UndefinedBehaviorSanitizer can not provide additional info.
SUMMARY: UndefinedBehaviorSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0x1689a9) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58) 
==18==ABORTING
"""


def test_undefined_behavior_report():
    report = extract_sanitizer_report(undefined_bahavior_log)

    assert report is not None

    assert (
        report
        == """==18==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x55bcaa07e6ec (pc 0x7fbeba6e19a9 bp 0x7fffc1a6d1e0 sp 0x7fffc1a6d1a8 T18)
==18==The signal is caused by a WRITE memory access.
    #0 0x7fbeba6e19a9  (/lib/x86_64-linux-gnu/libc.so.6+0x1689a9) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #1 0x55bcd8df84cf in memcpy /usr/include/x86_64-linux-gnu/bits/string_fortified.h:34:10
    #2 0x55bcd8df84cf in vfread(void*, long, void*) /src/libsndfile/ossfuzz/sndfile_fuzzer.cc:54:3
    #3 0x55bcd8e3edb2 in psf_fread /src/libsndfile/src/file_io.c:311:10
    #4 0x55bcd8e352e6 in header_read /src/libsndfile/src/common.c:857:12
    #5 0x55bcd8e34e47 in psf_binheader_readf /src/libsndfile/src/common.c
    #6 0x55bcd8e09c4e in caf_read_header /src/libsndfile/src/caf.c:395:3
    #7 0x55bcd8e09c4e in caf_open /src/libsndfile/src/caf.c:127:17
    #8 0x55bcd8df9295 in psf_open_file /src/libsndfile/src/sndfile.c:3180:13
    #9 0x55bcd8df8329 in LLVMFuzzerTestOneInput /src/libsndfile/ossfuzz/sndfile_fuzzer.cc:99:13
    #10 0x55bcd8d5a8a0 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerLoop.cpp:614:13
    #11 0x55bcd8d45b15 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:327:6
    #12 0x55bcd8d4b5af in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerDriver.cpp:862:9
    #13 0x55bcd8d76852 in main /src/llvm-project/compiler-rt/lib/fuzzer/FuzzerMain.cpp:20:10
    #14 0x7fbeba59d082 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x24082) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58)
    #15 0x55bcd8d3dcfd in _start (/out/sndfile_fuzzer+0x62cfd)

DEDUP_TOKEN: memcpy--vfread(void*, long, void*)
UndefinedBehaviorSanitizer can not provide additional info.
SUMMARY: UndefinedBehaviorSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0x1689a9) (BuildId: 0323ab4806bee6f846d9ad4bccfc29afdca49a58) 
==18==ABORTING
"""
    )


@pytest.mark.slow
def test_asan_report(
    detection_c_asc_nginx_cpv_1: tuple[Path, Path],
):
    context, detection = AIxCCContextBuilder(
        *detection_c_asc_nginx_cpv_1,
    ).build(
        previous_action=HeadAction(),
    )
    environment = context["pool"].restore(context)
    report = None

    try:
        environment.run_pov(context, detection)
    except ChallengePoVFoundError as e:
        report = extract_sanitizer_report(e.stdout.decode(errors="replace"))

    assert report is not None
    assert "ERROR: AddressSanitizer: heap-buffer-overflow on address" in report
