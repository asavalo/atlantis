from crete.commons.crash_analysis.functions.jazzer_crash import jazzer_output_preprocess
from crete.commons.crash_analysis.functions.userland_crash import (
    userland_output_preprocess,
)
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY


def test_c_cpp_crash_output_preprocessing():
    # The crash logs are configured incorrectly. Need to fix them.
    excluded_logs = {
        # These contain ANSI escape codes.
        "projects/aixcc/c/mock-c-for-patching/.aixcc/crash_logs/ossfuzz-1/cpv_0.log",
        "projects/aixcc/c/mock-c-for-patching/.aixcc/crash_logs/ossfuzz-2/cpv_1.log",
        # These are not crash logs but just error tokens.
        "projects/aixcc/c/timeouts-and-crashes/.aixcc/crash_logs/timeout_harness/cpv_1.log",
        "projects/aixcc/c/timeouts-and-crashes/.aixcc/crash_logs/signal_harness/cpv_0.log",
    }

    crash_log_pattern = "projects/aixcc/[c|cpp]/*/.aixcc/crash_logs/*/*.log"
    for crash_log_path in OSS_FUZZ_DIRECTORY.glob(crash_log_pattern):
        relative_path = str(crash_log_path.relative_to(OSS_FUZZ_DIRECTORY))
        if relative_path in excluded_logs:
            continue

        crash_log = crash_log_path.read_bytes()
        blocks = userland_output_preprocess(crash_log)
        assert len(blocks) > 0, f"Failed to preprocess crash log: {crash_log_path}"


def test_jvm_crash_output_preprocessing():
    crash_log_pattern = "projects/aixcc/jvm/*/.aixcc/crash_logs/*/*.log"
    for crash_log_path in OSS_FUZZ_DIRECTORY.glob(crash_log_pattern):
        crash_log = crash_log_path.read_bytes()
        blocks = jazzer_output_preprocess(crash_log)
        assert len(blocks) > 0, f"Failed to preprocess crash log: {crash_log_path}"
