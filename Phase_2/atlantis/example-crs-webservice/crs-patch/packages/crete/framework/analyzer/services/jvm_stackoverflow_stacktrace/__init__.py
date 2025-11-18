import re

from python_oss_fuzz.debugger.jdb import run_jdb_commands

from crete.atoms.detection import Detection
from crete.framework.evaluator.contexts import EvaluatingContext


class JVMStackOverflowStacktraceAnalyzer:
    # TODO: cache it
    def analyze(self, context: EvaluatingContext, detection: Detection) -> str | None:
        assert detection.language == "jvm", (
            "JVMStackOverflowStacktraceAnalyzer is only supported for JVM projects"
        )
        context["logger"].info("Analyzing JVM stackoverflow stacktrace")

        context["pool"].use(context, "DEBUG")

        project_name = detection.project_name
        harness_name = detection.blobs[0].harness_name
        blob = detection.blobs[0].blob
        commands = [
            "catch java.lang.StackOverflowError",
            "cont",
            "where",
        ]

        out = run_jdb_commands(project_name, harness_name, blob, commands)
        if out[2] is None:
            context["logger"].warning("No jdb output found")
            return None

        raw_stacktrace = out[2].split("where", 1)[-1].strip("\n")

        compact_stacktrace = deduplicate_consecutive_frames(raw_stacktrace)
        context["logger"].info("Stacktrace: %s", compact_stacktrace)
        return compact_stacktrace


def _is_same_block(block1: list[str], block2: list[str]) -> bool:
    """
    block format (example):
        [8,081] java.util.AbstractSet.hashCode (AbstractSet.java:124)
        [8,082] java.util.AbstractSet.hashCode (AbstractSet.java:124)
    """

    def annonimize_block(block: str) -> str:
        return re.sub(r"\[\d[\d,]*\]", "[<anon>]", block, flags=re.DOTALL)

    return all(
        annonimize_block(b1) == annonimize_block(b2) for b1, b2 in zip(block1, block2)
    )


def deduplicate_consecutive_frames(
    stacktrace: str, max_cycle_size: int = 5, repeat_threshold: int = 3
) -> str:
    assert max_cycle_size > 0, "max_cycle_size must be positive"
    assert repeat_threshold >= 3, (
        "repeat_threshold must be at least 3 to insert '... (repeated N times)' with previous line and next line"
    )

    i = 0
    result: list[str] = []
    lines = stacktrace.split("\n")
    while i < len(lines):
        found_repeat = False
        for cycle_size in range(1, max_cycle_size + 1):
            block = lines[i : i + cycle_size]
            j = i + cycle_size
            repeat_count = 0
            while j + cycle_size < len(lines) and _is_same_block(
                block, lines[j : j + cycle_size]
            ):
                repeat_count += 1
                j += cycle_size
            if repeat_count >= repeat_threshold:
                result.extend(block)
                result.append("... (repeated %d times)" % (repeat_count - 1))
                result.extend(lines[j - cycle_size : j])
                i = j
                found_repeat = True
                break
        if not found_repeat:
            result.append(lines[i])
            i += 1
    return "\n".join(result)
