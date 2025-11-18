BUG_CLASS_PATTERNS = [
    # c/c++
    r"ERROR: (AddressSanitizer: [\w-]+): ",
    r"ERROR: (AddressSanitizer: [\w-]+) ",
    r"ERROR: (AddressSanitizer: global-buffer-overflow)",
    r"ERROR: (UndefinedBehaviorSanitizer: [\w-]+) ",
    r"ERROR: (ThreadSanitizer: [\w-]+) ",
    r"(runtime error: .+): ",
    r"(MemorySanitizer: [\w-]+) ",
    r"(LeakSanitizer: ([\w-]+) )",
    # java
    r"== Java Exception: (com.code_intelligence.jazzer.api.FuzzerSecurityIssue\w+: .+):",
    r"== Java Exception: (com.code_intelligence.jazzer.api.FuzzerSecurityIssue\w+: .+)",
    r"== Java Exception: ([\w.]+Error): ",
    r"== Java Exception: ([\w.]+Exception): ",
    # python
    r"===BUG DETECTED: (PySecSan: .+) ===",
    r"=== (Uncaught Python exception): ===",
    r"(Uncaught Exception): Error: Check index! Data Corrupted!",
    # libfuzzer
    r"== ERROR: libFuzzer: (.*)",
]
