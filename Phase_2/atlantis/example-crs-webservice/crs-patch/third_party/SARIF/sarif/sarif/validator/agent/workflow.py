import typing
import inspect
import argparse
import base64
from loguru import logger
import sys
import json
import uuid
import os
import logging
import re

from langchain_openai import ChatOpenAI
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.runnables.config import RunnableConfig
from langgraph.graph import (  # pylint: disable=import-error, no-name-in-module
    END,
    START,
    StateGraph,
)
from langchain.globals import set_debug

from sarif.sarif.validator.agent.nodes import ValidationNode, RetrieverNode
from sarif.sarif.validator.agent.state import SarifValidationState
from sarif.sarif.validator.agent.state import SarifValidationAction
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)


class SarifValidationAgent:
    def __init__(self, llm: BaseChatModel, src_dir: str) -> None:
        self.src_dir = src_dir
        self.llm = llm

        self.validation_node = ValidationNode(llm)
        self.retriever_node = RetrieverNode()

        self.graph_builder = StateGraph(SarifValidationState)
        self.graph_builder.add_node("validation", self.validation_node)  # type: ignore
        self.graph_builder.add_node("retriever", self.retriever_node)  # type: ignore
        # self.graph_builder.add_node("router", self.router_function)  # type: ignore

        self.graph_builder.add_edge(START, "validation")
        self.graph_builder.add_conditional_edges(
            "validation",
            self.router_function,
        )
        self.graph_builder.add_edge("retriever", "validation")

        self._compiled_graph = self.graph_builder.compile()  # type: ignore

    def invoke(
        self,
        sarif: str,
        testcase: typing.Optional[str] = None,
        crash_log: typing.Optional[str] = None,
        patch_diff: typing.Optional[str] = None,
    ) -> dict[str, typing.Any] | typing.Any:
        state = SarifValidationState(
            sarif=sarif,
            src_dir=self.src_dir,
        )
        return self._compiled_graph.invoke(state)

    def router_function(self, state: SarifValidationState) -> str:
        match state.next_action:
            case SarifValidationAction.VALIDATE.value:
                return "validation"
            case SarifValidationAction.RETRIEVE.value:
                return "retriever"
            case _:
                return END


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

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

    model = "claude-3-7-sonnet-20250219"
    llm = ChatOpenAI(model=model)
    state = SarifValidationState(
        sarif=sarif,
        src_dir="/home/kyuheon/example-libpng",
    )

    agent = SarifValidationAgent(llm, "/home/kyuheon/example-libpng")

    result = agent.invoke(sarif)
    print(result)
