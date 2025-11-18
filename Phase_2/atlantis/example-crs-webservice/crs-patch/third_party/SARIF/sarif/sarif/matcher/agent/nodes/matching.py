import inspect
import base64
import re
import json
from loguru import logger

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


class MatchingNode:
    USER_PROMPT = inspect.cleandoc(
        """You are a cybersecurity expert.

Your mission is to analyze a given SARIF report, associated source code for the SARIF finding, and potentially crash information (crash log, patch) to determine if the SARIF report describes or is **causally related to** the same underlying security vulnerability (potentially a CVE) as indicated by the other pieces of information. **You should particularly focus on inferring the root cause and trigger conditions of the vulnerability from each piece of information and use this as a key basis for your correlation analysis and judgment.** A SARIF finding should be considered `MATCHED` even if it doesn't pinpoint the exact vulnerability location, as long as it identifies a code region that **contributes to the root cause or is integral to meeting the trigger conditions** for the *specific vulnerability instance* evidenced by the crash or patch.

**Crucially, if the SARIF finding and the crash/patch information point to similar *general types* of vulnerabilities but describe *fundamentally different trigger conditions* (e.g., requiring different types of user inputs, exploiting distinct logical flows that are not interdependent, or operating on distinct sensitive data under different preconditions for the *specific observed event*), or are in *unrelated code paths* that cannot both be part of the same exploitation chain for the observed crash/patch, they should generally be considered `NOT_MATCHED` unless a clear, direct, and demonstrable causal link for *that specific instance* can be established from the provided information. The presence of a similar vulnerability *pattern* or *CWE classification* in different parts of the code does not automatically mean they are the *same* vulnerability instance or causally related in the context of a single exploitable event.**

The information provided will be as follows:

<sarif_report>
{sarif}
</sarif_report>

<sarif_code_snippet>
{source_code_for_sarif_location}
</sarif_code_snippet>

<crash_log>
{crash_log}
</crash_log>

<patch_diff>
{patch_diff}
</patch_diff>

Your goal is twofold:
1.  Provide a probability score, between 0.0 and 1.0, that the SARIF report describes or is causally related to the same underlying security vulnerability as the other information. This score reflects your confidence in this correlation.
2.  Determine the next action: `MATCHED` if you are confident they describe or are causally related to the same vulnerability (as defined above), `NOT_MATCHED` if you are confident they do not, or `RETRIEVE` if crucial additional source code information (beyond what was initially provided for the SARIF location) is missing or requires verification to make a confident determination.

Please follow these steps for your analysis:

1.  **Individual Information Analysis:**
    * **SARIF Report and Code Snippet Analysis:**
        * What is the type (e.g., CWE ID) and severity of the reported vulnerability? Does it suggest a known type of security weakness? **(Note: CWE ID similarity alone is not sufficient for a match).**
        * What is the precise code location (file path, function name, class name, line number, key variables or data structures involved) where the vulnerability or related condition is indicated in the SARIF report?
        * Review the provided `<sarif_code_snippet>`. How does this code snippet relate to the vulnerability described in the SARIF report?
        * What is the cause or attack vector of the vulnerability as described in the report and observed in the `<sarif_code_snippet>`, and what potential **root cause(s)** and **fundamental trigger condition(s)** (including specific types of inputs, sequences of operations, exploitable states, or preconditions required) can be inferred from this combined information?
    * **Crash Log Analysis (if provided):**
        * What is the error message at the time of the crash?
        * If a stack trace is available, what is the function call stack at the point of the crash?
        * Are there any key register values or memory state information related to the crash? **What specific inputs, data manipulations, or system states seem to be involved based on the crash context?**
        * Which module or library did the crash occur in?
        * What can be inferred about the **root cause** or **fundamental trigger condition(s)** (including specific types of inputs, sequences of operations, or state that led to the crash) of the vulnerability from the crash information (error message, stack trace, etc.)?
    * **Patch Analysis (if provided):**
        * Which files and what parts of those files does the patch modify? (Modified functions, classes, line numbers, key variables or data structures affected)
        * What type of problem do the changes in the patch appear toaddress? (e.g., adding input validation, fixing a memory management error, changing logic indicative of a security fix)
        * Comparing the code before and after the patch, what specific vulnerability or bug is it intended to fix, what **root cause** does it appear to address, and what **fundamental trigger condition(s)** (including specific types of inputs, sequences, or states it aims to prevent or make non-exploitable) is it designed to prevent?

2.  **Cross-Correlation Analysis:**
    * Does the vulnerability location identified in the SARIF report (and visualized with the `<sarif_code_snippet>`) match, closely align with, or represent a **causally antecedent code region** to the code location modified by the patch and/or the location indicated by the crash log? For example, does the SARIF report, supported by the provided snippet, identify an issue in a function that produces a value or state later misused, leading to the crash?
    * Is there a strong logical connection between the vulnerability cause described in the SARIF report (and evident in the `<sarif_code_snippet>`) and the type of issue implied by the crash log, and the problem addressed by the patch, suggesting they all point to or are part of a single, coherent security vulnerability chain?
    * **Specifically, compare the inferred root cause(s) and fundamental trigger condition(s) from each source. Do they describe the same necessary preconditions, sequences of user actions, types of malicious input, or exploitable system states? If the SARIF report indicates a vulnerability triggered by one set of conditions (e.g., exploiting a specific logical flaw in data processing via function A) in file 'File1.java', and the crash/patch relates to a different set of conditions (e.g., a malformed input structure processed by function B, or a race condition involving different resources) in file 'File2.java' (or even in 'File1.java' but a distinct, unlinked execution path), how strong is the evidence that these are not independent issues, even if their general CWE classification might be similar? Could the issue described in the SARIF report *directly and necessarily* lead to the *specific trigger conditions* that manifest the vulnerability fixed by the patch or observed in the crash?**
    * Even if the SARIF location is not the *exact* point of failure, does it, along with its code, highlight a condition or component that is logically necessary for the inferred root cause or **fundamental trigger conditions** of the *specific vulnerability instance observed in the crash/patch* to manifest? How does this consistency (or inconsistency) contribute to the overall understanding?
    * Identify any ambiguities or missing *additional* source code context (beyond the initially provided `<sarif_code_snippet>`) that prevents a conclusive correlation, especially in establishing this causal link. For instance, are other functions or files, referenced by the snippet, patch, or crash log, needed for a full understanding, **particularly if the SARIF report and crash/patch data point to different files, functions, or imply substantially different trigger mechanisms for the vulnerability?**

3.  **Probabilistic Judgment, Justification, and Next Action Determination:**
    * Based on the comprehensive analysis above, provide a probability score as a floating-point number between 0.0 and 1.0.
    * Clearly explain the detailed reasoning behind your judgment in the `<justification>` section. This explanation must detail how the inferred **root cause(s)** and **fundamental trigger condition(s)** from each piece of information (including the `<sarif_code_snippet>`), and their **causal relationships (or lack thereof)**, were considered as key factors in your determination. **Address explicitly if the fundamental trigger conditions (e.g., requiring different types of malformed input, exploiting different logical flaws, or affecting separate data components that do not interact for the specific observed event) seem distinct and mutually exclusive for a single vulnerability event.**
    * **Next Action Decision**:
        * If you are highly confident (reflected by a high probability score, e.g., > 0.7) that the SARIF report (and its associated code snippet) and other information describe or are **directly causally related to** the same underlying security vulnerability (as per the broadened definition in the mission statement), set `<next_action>` to `MATCHED`.
        * If you are highly confident (reflected by a low probability score, e.g., < 0.3) that they describe different issues or the causal link is weak/non-existent, **especially if the root causes or fundamental trigger conditions (e.g., requiring distinct and incompatible user actions for exploitation, different exploitable states, or affecting separate, non-interacting code paths for the *specific observed event*) are clearly distinct and cannot be reconciled into a single vulnerability exploitation chain for the observed event**, set `<next_action>` to `NOT_MATCHED`.
        * If your analysis is hindered by missing *additional* source code context (beyond the initially provided `<sarif_code_snippet>`), or if specific details are too ambiguous to make a confident `MATCHED` or `NOT_MATCHED` determination (especially regarding the causal link, precise root cause, or **whether seemingly different trigger mechanisms or code locations could still be part of the same vulnerability chain for the specific crash/patch event**), set `<next_action>` to `RETRIEVE`. **Lean towards `RETRIEVE` if the SARIF and crash/patch information point to different files, functions, or imply different core trigger mechanisms, and the provided snippets are insufficient to confirm or deny a direct causal link for the specific crash/patch event.**
    * **Retrieval Query (if `RETRIEVE` is chosen)**:
        * If `<next_action>` is `RETRIEVE`, you must provide a single, specific query string in the `<retrieve_query>` tag. This query should request the most critical piece of *additional* source code needed to resolve the ambiguities identified in your `<correlation_analysis>` and `<justification>`.
        * The `retrieve_query` must follow the "BY_LINENO" format: `BY_LINENO:file_path:start_line-end_line`.
            * `file_path`: Use the relative file path as found in the SARIF report or other input data (e.g., `vuln.c`, `vuln/test.c`).
            * Line specifications:
                * `:-N`: Retrieve lines from the start of the file up to and including line N (e.g., `BY_LINENO:vuln.c:-3` retrieves lines 1-3).
                * `N-`: Retrieve lines from line N to the end of the file (e.g., `BY_LINENO:vuln/test.c:4-` retrieves lines from 4 to end).
                * `N-M`: Retrieve lines from N to M, inclusive (e.g., `BY_LINENO:png/pngutil.c:10-10` retrieves only line 10. `BY_LINENO:src/main.c:5-15` retrieves lines 5 through 15).
                * `:-`: Retrieve the entire file (e.g., `BY_LINENO:fuzz/fuzz.c:-`).
        * Your `<justification>` must explain why this specific *additional* code snippet is essential for your next analysis step, particularly in clarifying the **root cause**, **fundamental trigger condition(s)**, or the **causal link** between the SARIF finding and the observed vulnerability, and how it will help achieve a `MATCHED` or `NOT_MATCHED` determination by resolving these ambiguities, given that the initial SARIF-related code was already provided. **Explain how the requested code will help determine if different inferred trigger mechanisms or code locations are part of the same exploitable vulnerability or represent distinct issues.**

Please provide your response in the following format:

<analysis_report>
  <sarif_summary>
    - Vulnerability Type: [CWE-ID or description (Note: CWE is for context, not primary matching evidence), or "N/A" if not determinable]
    - Vulnerability Location: [File path:line number, Function/Class name, Key data structures/variables involved, or "N/A"]
    - Provided Source Context: [Brief description of the provided sarif_code_snippet and its relevance, or "N/A"]
    - Inferred Root Cause: [Inferred root cause based on SARIF information and sarif_code_snippet, or "N/A"]
    - Inferred Trigger Condition: [Inferred fundamental trigger condition based on SARIF information and sarif_code_snippet, detailing necessary preconditions, input types, or exploitable states, or "N/A"]
    - Key Details: [Summary of the core content of the SARIF report in conjunction with the provided code, or "N/A"]
  </sarif_summary>

  <crash_log_summary>
    - Error Message: [Main error message, or "N/A" if not provided/determinable]
    - Crash Location: [Key functions or modules from the stack trace, Relevant data manipulations/inputs if identifiable, or "N/A"]
    - Inferred Root Cause: [Inferred root cause based on crash log information, or "N/A"]
    - Inferred Trigger Condition: [Inferred fundamental trigger condition based on crash log information, detailing necessary preconditions, input types, or states leading to the crash, or "N/A"]
    - Key Details: [Summary of the core content of the crash log, or "N/A"]
  </crash_log_summary>

  <patch_summary>
    - Modification Location: [File path:line number, Function/Class name of changes, Key data structures/variables affected, or "N/A" if not provided/determinable]
    - Modification Content: [Summary of key logic changes or fixes in the patch, or "N/A"]
    - Addressed Root Cause: [Root cause the patch aims to address, or "N/A"]
    - Prevented Trigger Condition: [Fundamental trigger condition the patch aims to prevent, detailing specific preconditions, input types, or states it mitigates, or "N/A"]
    - Intended Fix: [Estimated type of problem or vulnerability the patch aims to resolve, or "N/A"]
  </patch_summary>

  <correlation_analysis>
  [Detailed analysis of the correlation between the SARIF report (with its provided code snippet) and the other pieces of information. Explain points of consistency, inconsistency, and why they are significant, especially regarding the inferred **root cause(s)**, **fundamental trigger condition(s) (paying close attention to the specific sequence of operations, necessary inputs, exploitable states, or system preconditions required)**, and their **causal links** from each source. Clearly state any ambiguities or missing *additional* source code context that affects confidence or necessitates retrieval, **particularly if different core trigger mechanisms or code locations are involved**.]
  </correlation_analysis>

  <probability_score>
  [Probability value between 0.0 and 1.0. This score underpins the next_action.]
  </probability_score>

  <justification>
  [A comprehensive and logical explanation for the assigned probability score and the next_action. This explanation must detail how the inferred **root cause(s)**, **fundamental trigger condition(s) (with emphasis on comparing the actual mechanisms of exploitation and required preconditions, rather than just general CWE types)**, and their **causal relationships (or clear lack thereof)** from each piece of information (including the initial `<sarif_code_snippet>`) were considered as key factors in your determination. **If fundamental trigger conditions for the specific observed event seem distinct and mutually exclusive, explain why this leads to `NOT_MATCHED`.** If RETRIEVE is chosen, detail why the current information (including the initially provided snippet) is insufficient, particularly in clarifying the **root cause**, **fundamental trigger condition(s)**, or the **causal link when different trigger mechanisms or code locations are involved**, and how the requested *additional* source code (via retrieve_query) will help achieve a MATCHED or NOT_MATCHED determination by resolving these ambiguities.]
  </justification>

  <next_action>
  [MATCHED, NOT_MATCHED, or RETRIEVE]
  </next_action>

  <retrieve_query>
  [This tag is ONLY present if <next_action> is RETRIEVE. Otherwise, omit this tag entirely. Contains a single query string, e.g., "BY_LINENO:src/example.c:10-20"]
  </retrieve_query>
</analysis_report>"""
    )

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def __call__(self, state: SarifMatchingState) -> SarifMatchingState:
        def hexdump(data: bytes, bytes_per_line: int = 16) -> str:
            lines = []
            for i in range(0, len(data), bytes_per_line):
                chunk = data[i : i + bytes_per_line]
                # Hex portion
                hex_part = " ".join([f"{b:02x}" for b in chunk])
                hex_part = hex_part.ljust(bytes_per_line * 3 - 1)  # Pad with spaces

                # ASCII portion
                ascii_part = "".join([chr(b) if 32 <= b <= 126 else "." for b in chunk])

                # Line number and complete line
                line_num = f"{i:08x}"
                lines.append(f"{line_num}: {hex_part}  {ascii_part}")

            return "\n".join(lines)

        if len(state.messages) == 0:
            logger.info("Matching node called for the first time")
            sarif = state.sarif
            if state.testcase:
                testcase = hexdump(base64.b64decode(state.testcase))
            else:
                testcase = ""
            if state.crash_log:
                crash_log = inspect.cleandoc(state.crash_log)
            else:
                crash_log = ""
            if state.patch_diff:
                patch_diff = inspect.cleandoc(state.patch_diff)
            else:
                patch_diff = ""

            source_code_for_sarif_location = ""
            retriever = ByLinenoRetriever(state.src_dir)
            # locations = AIxCCSarif.model_validate(sarif).runs[0].results[0].locations
            locations = json.loads(sarif)["runs"][0]["results"][0].get(
                "locations", None
            )
            if locations is not None:
                for location in filter(
                    lambda loc: loc.get("physicalLocation", None) is not None,
                    locations,
                ):
                    phyloc = location["physicalLocation"]
                    if (
                        phyloc.get("artifactLocation", None) is None
                        or phyloc["artifactLocation"].get("uri", None) is None
                        or phyloc.get("region", None) is None
                    ):
                        continue
                    file_path = phyloc["artifactLocation"]["uri"]
                    start_line = phyloc["region"].get("startLine", "")
                    end_line = phyloc["region"].get("endLine", "")
                    retrieved = retriever(
                        f"BY_LINENO:{file_path}:{start_line}-{end_line}"
                    )
                    source_code_for_sarif_location += retrieved + "\n\n"

            user_prompt = self.USER_PROMPT.format(
                sarif=sarif,
                source_code_for_sarif_location=source_code_for_sarif_location,
                crash_log=crash_log,
                patch_diff=patch_diff,
            )
            state.messages = [HumanMessage(content=user_prompt)]
            logger.debug(f"User: {user_prompt}")
            # state.next_action = SarifMatchingAction.RETRIEVE
            # state.retrieve_query = "BY_LINENO:pngrutil.c:-"
            # return state
        elif state.retrieved is not None:
            logger.debug(f"Retrieved: {state.retrieved}")
            state.messages.append(HumanMessage(content=state.retrieved))
            state.retrieved = None

        completion = self.llm.invoke(state.messages)

        input_tokens = completion.usage_metadata["input_tokens"]
        output_tokens = completion.usage_metadata["output_tokens"]
        logger.debug(f"Token Usage: Input={input_tokens}, Output={output_tokens}")
        logger.debug(
            f"Estimated cost(claude-3-7-sonnet-20250219): {(input_tokens * 3 + output_tokens * 15) / 1000000} USD"
        )

        logger.debug(f"Completion: {completion.content}")
        state.messages.append(completion)

        next_action = (
            re.search(
                r"<next_action>\s*([^\s]*?)\s*</next_action>",
                state.messages[-1].content,
                re.DOTALL,
            )
            .group(1)
            .strip()
        )

        if next_action in [
            SarifMatchingAction.MATCHED.value,
            SarifMatchingAction.NOT_MATCHED.value,
        ]:
            logger.debug(f"Matching result determined: {next_action}")
            state.next_action = SarifMatchingAction(next_action).value
            return state
        elif next_action != SarifMatchingAction.RETRIEVE.value:
            logger.debug(f"Something went wrong: {next_action}")
            state.messages = state.messages[:-1]
            return state

        retrieve_query = (
            re.search(
                r"<retrieve_query>\s*([^\s]*?)\s*</retrieve_query>",
                state.messages[-1].content,
                re.DOTALL,
            )
            .group(1)
            .strip()
        )

        # match state.retrieve_query.split(":")[0]:
        #     case "BY_LINENO":
        #         retriever = ByLinenoRetriever(state.src_dir)
        #         retrieved = retriever(state)
        #         if retrieved is None:
        #             return {"messages": state.messages[:-1]}
        #     case _:
        #         return {"messages": state.messages[:-1]}

        state.next_action = SarifMatchingAction.RETRIEVE.value
        state.retrieve_query = retrieve_query
        return state


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
    )
    matcher = MatchingNode(llm)
    matcher(state)
    print(state.messages[-1].content)
