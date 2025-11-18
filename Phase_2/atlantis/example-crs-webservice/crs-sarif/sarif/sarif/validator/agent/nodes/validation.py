import inspect
import base64
import re
import json
from loguru import logger

import langchain
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

langchain.debug = True

from sarif.sarif.validator.agent.state import (
    SarifValidationState,
    SarifValidationAction,
)
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.sarif.validator.agent.retrievers.by_lineno_retriever import ByLinenoRetriever


class ValidationNode:
    USER_PROMPT = inspect.cleandoc(
        """You are a cybersecurity expert.

Your mission is to analyze a given SARIF report (specifically, one finding from it) and the source code snippet for the location it points to. You may also retrieve additional source code information if necessary. Your goal is to determine if the SARIF report describes a **valid** security vulnerability warning.

**Definition of a Valid SARIF Report:**
A SARIF report is considered valid if the code location it points to meets one or more of the following criteria:
1.  The location is the **direct cause** of a bug.
2.  The location **directly contributes** to triggering or exploiting a vulnerability, or is **indirectly involved in satisfying the conditions** for a vulnerability to occur.
3.  Overall, the location provides a **significant clue** to discovering and understanding the specified type of vulnerability.

**Definition of an Invalid SARIF Report:**
A SARIF report is considered invalid in the following cases:
1.  **Actually Untriggerable:** Although the code might appear to contain a bug, the execution path to that code point does not realistically exist (e.g., dead code), or there are strong filtering mechanisms in between that prevent the vulnerability from actually being triggered.
2.  **Irrelevant Location:** The code location is logically or functionally unrelated to the type of vulnerability described in the SARIF report.
3.  **Lack of Logical Connection:** The root cause, trigger conditions, or exploit process of a potential vulnerability are deemed to have no direct or indirect logical connection to what the SARIF report indicates at that code location.

The information provided will be as follows:

<sarif_report>
{sarif_finding}
</sarif_report>

<code_snippet>
{source_code_for_sarif_location}
</code_snippet>

Your goal is twofold:
1.  Provide a probability score, between 0.0 and 1.0, that the SARIF report is valid according to the definitions above. This score reflects your confidence level.
2.  Determine the next action: `VALID` (if you are confident it's a valid warning), `INVALID` (if you are confident it's an invalid warning), or `RETRIEVE` (if crucial additional source code information is missing to make a confident determination).

Please follow these steps for your analysis:

1.  **SARIF Report and Code Snippet Analysis:**
    * What is the type (e.g., CWE ID) and severity of the vulnerability indicated in the SARIF report? Does it suggest a known type of security weakness?
    * What is the precise code location (file path, function name, class name, line number, key variables or data structures involved) where the vulnerability or related condition is indicated?
    * Review the provided `<code_snippet>`. How does this code snippet relate to the vulnerability described in the SARIF report?
    * Based on the SARIF report's rule and the provided code snippet, what is the **alleged root cause** of the vulnerability potentially indicated, and what are the **potential fundamental trigger conditions** (including types of inputs, sequence of operations, or exploitable states that could lead to this type of vulnerability at this location)?
    * Based solely on the SARIF report and the snippet, are there any immediate signs that this warning might be an obvious false alarm (e.g., clear dead code within the snippet, an obvious misapplication of the SARIF rule)?

2.  **Plausibility and Exploitability Analysis (Hypothesis and Verification):**
    * Considering the potential vulnerability inferred in step 1, what specific inputs, states, or sequence of operations would be needed to trigger it at the reported location?
    * Are there any common mitigation or defensive coding patterns present *within the snippet itself* that might already prevent the issue described by the SARIF rule?
    * Under what conditions would this SARIF report be considered valid (i.e., what needs to be true about the surrounding code or call paths)?
    * Under what conditions would this SARIF report be considered invalid (e.g., if the code location is actually unreachable, if input values are always safely filtered, if it's logically irrelevant to the reported vulnerability type)?
    * If this SARIF report were valid, how would the code at this location contribute directly or indirectly to the occurrence of the vulnerability?

3.  **Assessment of Need for Additional Information (Potentially leading to RETRIEVE):**
    * Is the provided `<code_snippet>` sufficient to make a high-confidence judgment about the validity of the SARIF report (considering actual reachability, real impact, and the realism of necessary trigger conditions)?
    * What specific *additional* information (e.g., calling functions for the snippet, definitions of variables/functions used in the snippet but not defined there, relevant control flow leading to this point) is needed to confirm or deny the plausibility of the SARIF finding? Explain why this information is critical.

4.  **Probabilistic Judgment, Justification, and Next Action Determination:**
    * Based on the comprehensive analysis above, provide a probability score as a floating-point number between 0.0 and 1.0 for the SARIF report being valid.
    * In the `<justification>` section, clearly explain the detailed reasoning behind your judgment. This explanation must detail how the inferred **alleged root cause** and **potential fundamental trigger conditions** from the SARIF report and snippet relate to the definitions of a "Valid SARIF Report" and an "Invalid SARIF Report," specifically addressing factors like **code reachability, relevance to the reported vulnerability type, and logical connection**.
    * **Next Action Decision**:
        * `VALID`: If you have high confidence (e.g., probability score > 0.7) that the SARIF report is a valid warning or provides a very significant clue to a vulnerability.
        * `INVALID`: If you have high confidence (e.g., probability score < 0.3) that the SARIF report is an invalid warning (e.g., due to clear evidence of unreachability, irrelevance, or lack of logical connection).
        * `RETRIEVE`: If the current information (including the provided `<code_snippet>`) is insufficient to determine validity, and *additional* source code context is essential to clarify the **actual root cause, the feasibility of fundamental trigger conditions, code reachability, or logical connection**.
    * **Retrieval Query (if `RETRIEVE` is chosen)**:
        * If `<next_action>` is `RETRIEVE`, you must provide a `<retrieve_query>` tag.
        * The query must follow the "BY_LINENO" format: `BY_LINENO:file_path:start_line-end_line`.
            * `file_path`: Use the relative file path as found in the SARIF report or other input data (e.g., `vuln.c`, `vuln/test.c`).
            * Line specifications:
                * `:-N`: Retrieve lines from the start of the file up to and including line N (e.g., `BY_LINENO:vuln.c:-3` retrieves lines 1-3).
                * `N-`: Retrieve lines from line N to the end of the file (e.g., `BY_LINENO:vuln/test.c:4-` retrieves lines from 4 to end).
                * `N-M`: Retrieve lines from N to M, inclusive (e.g., `BY_LINENO:png/pngutil.c:10-10` retrieves only line 10. `BY_LINENO:src/main.c:5-15` retrieves lines 5 through 15).
                * `:-`: Retrieve the entire file (e.g., `BY_LINENO:fuzz/fuzz.c:-`).
        * Your `<justification>` must explain why this specific *additional* code snippet is essential for your next analysis step, particularly in **determining the actual exploitability of the potential vulnerability (reachability, feasibility of trigger conditions, etc.) and clarifying whether the SARIF report's claim is plausible**, and how it will help achieve a `VALID` or `INVALID` determination.

Please provide your response in the following format:

<sarif_validation_report>
  <sarif_summary>
    - Vulnerability Type: [CWE-ID or description, or "N/A" if not determinable]
    - Vulnerability Location: [File path:line number, Function/Class name, Key data structures/variables involved, or "N/A"]
    - Provided Source Context: [Brief description of the provided code_snippet and its relevance to the SARIF report, or "N/A"]
    - Alleged Root Cause (from SARIF & Snippet): [Inferred alleged root cause of the potential vulnerability based on the SARIF report and snippet, or "N/A"]
    - Potential Trigger Condition (from SARIF & Snippet): [Inferred potential fundamental trigger conditions for the alleged vulnerability based on the SARIF report and snippet, or "N/A"]
    - Key Details of SARIF Finding: [Summary of the core content of the SARIF report in conjunction with the provided code, or "N/A"]
  </sarif_summary>

  <plausibility_and_exploitability_analysis>
  [Detailed analysis of the plausibility of the SARIF report's claim, the potential exploitability of the inferred vulnerability based on the code snippet (considering reachability, filtering, presence of defensive code, etc.), and the conditions under which the SARIF report would be considered valid or invalid. State if a judgment cannot be made without more information and why.]
  </plausibility_and_exploitability_analysis>

  <probability_score>
  [Probability value between 0.0 and 1.0 that the SARIF report is valid.]
  </probability_score>

  <justification>
  [A comprehensive and logical explanation for the assigned probability score and the next_action. This explanation must detail how the inferred **alleged root cause** and **potential fundamental trigger conditions** from the SARIF report and code snippet were considered in relation to the definitions of a "Valid SARIF Report" and an "Invalid SARIF Report" (especially regarding **code reachability, relevance to the reported vulnerability type, and logical connection**). If RETRIEVE is chosen, detail why the current information (including the initially provided snippet) is insufficient, and how the requested *additional* source code will help in **determining the actual exploitability of the potential vulnerability and clarifying the plausibility of the SARIF claim**.]
  </justification>

  <next_action>
  [VALID, INVALID, or RETRIEVE]
  </next_action>

  <retrieve_query>
  [This tag is ONLY present if <next_action> is RETRIEVE. Otherwise, omit this tag entirely. Contains a single query string, e.g., "BY_LINENO:src/example.c:10-20"]
  </retrieve_query>
</sarif_validation_report>"""
    )

    def __init__(self, llm: BaseChatModel):
        self.llm = llm

    def __call__(self, state: SarifValidationState) -> SarifValidationState:
        if len(state.messages) == 0:
            logger.info("Matching node called for the first time")
            sarif = state.sarif

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
                sarif_finding=sarif,
                source_code_for_sarif_location=source_code_for_sarif_location,
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
            SarifValidationAction.VALID.value,
            SarifValidationAction.INVALID.value,
        ]:
            logger.debug(f"Validation result determined: {next_action}")
            state.next_action = SarifValidationAction(next_action).value
            return state
        elif next_action != SarifValidationAction.RETRIEVE.value:
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

        state.next_action = SarifValidationAction.RETRIEVE.value
        state.retrieve_query = retrieve_query
        return state


if __name__ == "__main__":
    sarif = """{
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
                                            "uri": "pngrutil.c"
                                        },
                                        "region": {
                                            "endLine": 1447,
                                            "startColumn": 1,
                                            "startLine": 1421
                                        }
                                    }
                                }
                            ],
                            "message": {"text": "Associated risk: CWE-121"},
                            "partialFingerprints": {
                                "primaryLocationLineHash": "22ac9f8e7c3a3bd8:8"
                            },
                            "properties": {
                                "github/alertNumber": 2,
                                "github/alertUrl": "https://api.github.com/repos/aixcc-finals/example-libpng/code-scanning/alerts/2"
                            },
                            "rule": {"id": "CWE-121", "index": 0},
                            "ruleId": "CWE-121"
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
                                    "shortDescription": {"text": "CWE #CWE-121"}
                                }
                            ],
                            "version": "1.0.0"
                        }
                    },
                    "versionControlProvenance": [
                        {
                            "branch": "refs/heads/challenges/full-scan",
                            "repositoryUri": "https://github.com/aixcc-finals/example-libpng",
                            "revisionId": "fdacd5a1dcff42175117d674b0fda9f8a005ae88"
                        }
                    ]
                }
            ],
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0"
        }"""

    from langchain_openai import ChatOpenAI

    model = "claude-3-7-sonnet-20250219"
    llm = ChatOpenAI(model=model)
    state = SarifValidationState(
        sarif=sarif,
        src_dir="/home/kyuheon/example-libpng",
    )
    validator = ValidationNode(llm)
    validator(state)
    print(state.messages[-1].content)
