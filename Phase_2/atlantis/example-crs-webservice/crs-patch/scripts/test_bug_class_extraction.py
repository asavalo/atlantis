from crete.commons.crash_analysis.functions import extract_bug_class
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY

for crash_log_path in OSS_FUZZ_DIRECTORY.glob(
    "projects/aixcc/*/*/.aixcc/crash_logs/*/*.log"
):
    crash_log = crash_log_path.read_text()
    bug_class = extract_bug_class(crash_log)
    print(f"{crash_log_path}: {bug_class}")
    if bug_class is None:
        raise Exception("Bug class not found")
print("DONE!")
