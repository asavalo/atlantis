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

from sarif.sarif.matcher.agent.nodes import MatchingNode, RetrieverNode
from sarif.sarif.matcher.agent.state import SarifMatchingState
from sarif.sarif.matcher.agent.state import SarifMatchingAction
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)


class SarifMatchingAgent:
    def __init__(self, llm: BaseChatModel, src_dir: str) -> None:
        self.src_dir = src_dir
        self.llm = llm

        self.matching_node = MatchingNode(llm)
        self.retriever_node = RetrieverNode()

        self.graph_builder = StateGraph(SarifMatchingState)
        self.graph_builder.add_node("matching", self.matching_node)  # type: ignore
        self.graph_builder.add_node("retriever", self.retriever_node)  # type: ignore
        # self.graph_builder.add_node("router", self.router_function)  # type: ignore

        self.graph_builder.add_edge(START, "matching")
        self.graph_builder.add_conditional_edges(
            "matching",
            self.router_function,
        )
        self.graph_builder.add_edge("retriever", "matching")

        self._compiled_graph = self.graph_builder.compile()  # type: ignore

    def invoke(
        self,
        sarif: str,
        testcase: typing.Optional[str] = None,
        crash_log: typing.Optional[str] = None,
        patch_diff: typing.Optional[str] = None,
    ) -> dict[str, typing.Any] | typing.Any:
        state = SarifMatchingState(
            sarif=sarif,
            testcase=testcase,
            crash_log=crash_log,
            patch_diff=patch_diff,
            src_dir=self.src_dir,
        )
        return self._compiled_graph.invoke(state)

    def router_function(self, state: SarifMatchingState) -> str:
        match state.next_action:
            case SarifMatchingAction.MATCHING.value:
                return "matching"
            case SarifMatchingAction.RETRIEVE.value:
                return "retriever"
            case _:
                return END


if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stdout, level="INFO")

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--model", type=str, required=False, default="claude-3-7-sonnet-20250219"
    )
    parser.add_argument("--log-dir", type=str, required=False, default="./logs")

    subparsers = parser.add_subparsers(dest="command", required=True)

    single_parser = subparsers.add_parser("single")
    single_parser.add_argument("--src", type=str, required=True)
    single_parser.add_argument("--sarif", type=str, required=True)
    single_parser.add_argument("--testcase", type=str, required=False, default=None)
    single_parser.add_argument("--crashlog", type=str, required=False, default=None)
    single_parser.add_argument("--patch", type=str, required=False, default=None)

    matched_eval_parser = subparsers.add_parser("matched_eval")
    matched_eval_parser.add_argument("--src", type=str, required=True)
    matched_eval_parser.add_argument("--oss-fuzz", type=str, required=True)
    matched_eval_parser.add_argument("--sarif", type=str, required=True)

    unmatched_eval_parser = subparsers.add_parser("unmatched_eval")
    unmatched_eval_parser.add_argument("--src", type=str, required=True)
    unmatched_eval_parser.add_argument("--oss-fuzz", type=str, required=True)
    unmatched_eval_parser.add_argument("--sarif", type=str, required=True)

    eval_parser = subparsers.add_parser("eval")
    eval_parser.add_argument("--src", type=str, required=True)
    eval_parser.add_argument("--oss-fuzz", type=str, required=True)
    eval_parser.add_argument("--sarif", type=str, required=True)

    args = parser.parse_args()

    def do(
        agent: SarifMatchingAgent,
        src: str,
        sarif: str,
        testcase: str,
        crashlog: str,
        patch: str,
        expected: typing.Optional[bool] = None,
        case_id: str = str(uuid.uuid4()),
    ) -> str:
        log_id = logger.add(f"{args.log_dir}/{case_id}.log", level="DEBUG")

        with open(sarif, "r") as f:
            sarif_data = AIxCCSarif.model_validate_json(f.read()).model_dump_json(
                indent=4
            )
        if testcase is not None:
            with open(testcase, "rb") as f:
                testcase_data = base64.b64encode(f.read()).decode("utf-8")
        else:
            testcase_data = None
        if crashlog is not None:
            with open(crashlog, "r") as f:
                crashlog_data = f.read()
        else:
            crashlog_data = None
        if patch is not None:
            with open(patch, "r") as f:
                patch_data = f.read()
        else:
            patch_data = None

        result = agent.invoke(sarif_data, testcase_data, crashlog_data, patch_data)

        logger.info(f"src: {src}")
        logger.info(f"sarif: {sarif}")
        logger.info(f"testcase: {testcase}")
        logger.info(f"crashlog: {crashlog}")
        logger.info(f"patch: {patch}")
        if expected is None:
            logger.info("Expected: None")
        elif expected:
            logger.info("Expected: MATCHED")
        else:
            logger.info("Expected: NOT_MATCHED")
        logger.info(f"Decision: {result['next_action']}")

        logger.remove(log_id)

        return result["next_action"]

    model = ChatOpenAI(model=args.model)

    match args.command:
        case "single":
            agent = SarifMatchingAgent(model, args.src)
            print(
                do(
                    agent,
                    args.src,
                    args.sarif,
                    args.testcase,
                    args.crashlog,
                    args.patch,
                )
            )
        case "matched_eval":
            sarifs = os.listdir(f"{args.sarif}/benchmarks/manual")
            for sarif in sarifs:
                # [c][asc-nginx][pov_harness][cpv_3].sarif
                match = re.match(
                    r"\[(?P<lang>[^]]+)\]\[(?P<project>[^]]+)\]\[(?P<harness>[^]]+)\]\[(?P<cpv>[^]]+)\].sarif",
                    sarif,
                )
                if match:
                    lang = match.group("lang")
                    project = match.group("project")
                    harness = match.group("harness")
                    cpv = match.group("cpv")
                else:
                    logger.error(f"Invalid sarif file: {sarif}")

                src = f"{args.src}/{project}"
                agent = SarifMatchingAgent(model, src)
                sarif = f"{args.sarif}/benchmarks/manual/{sarif}"
                testcase = f"{args.oss_fuzz}/projects/aixcc/{lang}/{project}/.aixcc/povs/{harness}/{cpv}"
                testcase = None
                crashlog = f"{args.oss_fuzz}/projects/aixcc/{lang}/{project}/.aixcc/crash_logs/{harness}/{cpv}.log"
                patch = f"{args.oss_fuzz}/projects/aixcc/{lang}/{project}/.aixcc/patches/{harness}/{cpv}.diff"
                expected = True
                case_id = f"[{lang}][{project}][{harness}][{cpv}]"

                try:
                    do(agent, src, sarif, testcase, crashlog, patch, expected, case_id)
                except Exception as e:
                    logger.error(f"Error: {e}")
                    continue
        case "unmatched_eval":
            sarifs = os.listdir(f"{args.sarif}/benchmarks/manual")
            harnesses = set()
            cases = set()
            for sarif in sarifs:
                # [c][asc-nginx][pov_harness][cpv_3].sarif
                match = re.match(
                    r"\[(?P<lang>[^]]+)\]\[(?P<project>[^]]+)\]\[(?P<harness>[^]]+)\]\[(?P<cpv>[^]]+)\].sarif",
                    sarif,
                )
                if match:
                    lang = match.group("lang")
                    project = match.group("project")
                    harness = match.group("harness")
                    harnesses.add((lang, project, harness))
                    cases.add((lang, project, harness, match.group("cpv")))

            for lang, project, harness in harnesses:
                cases_of_harness = list(
                    filter(
                        lambda x: x[0] == lang and x[1] == project and x[2] == harness,
                        cases,
                    )
                )
                for i in range(len(cases_of_harness)):
                    for j in range(i + 1, len(cases_of_harness)):
                        lang = cases_of_harness[i][0]
                        project = cases_of_harness[i][1]
                        harness = cases_of_harness[i][2]
                        sarif_cpv = cases_of_harness[i][3]
                        other_cpv = cases_of_harness[j][3]

                        src = f"{args.src}/{project}"
                        agent = SarifMatchingAgent(model, src)
                        sarif = f"{args.sarif}/benchmarks/manual/[{lang}][{project}][{harness}][{sarif_cpv}].sarif"
                        testcase = f"{args.oss_fuzz}/projects/aixcc/{lang}/{project}/.aixcc/povs/{harness}/{other_cpv}"
                        testcase = None
                        crashlog = f"{args.oss_fuzz}/projects/aixcc/{lang}/{project}/.aixcc/crash_logs/{harness}/{other_cpv}.log"
                        patch = f"{args.oss_fuzz}/projects/aixcc/{lang}/{project}/.aixcc/patches/{harness}/{other_cpv}.diff"
                        expected = False
                        case_id = (
                            f"[{lang}][{project}][{harness}][{sarif_cpv}-{other_cpv}]"
                        )

                        try:
                            do(
                                agent,
                                src,
                                sarif,
                                testcase,
                                crashlog,
                                patch,
                                expected,
                                case_id,
                            )
                        except Exception as e:
                            logger.error(f"Error: {e}")
                            continue
        case "eval":
            sarifs = os.listdir(f"{args.sarif}/benchmarks/manual")
            cases = list()
            for sarif in sarifs:
                # [c][asc-nginx][pov_harness][cpv_3].sarif
                match = re.match(
                    r"\[(?P<lang>[^]]+)\]\[(?P<project>[^]]+)\]\[(?P<harness>[^]]+)\]\[(?P<cpv>[^]]+)\].sarif",
                    sarif,
                )
                if match:
                    lang = match.group("lang")
                    project = match.group("project")
                    harness = match.group("harness")
                    cpv = match.group("cpv")
                    cases.append((lang, project, harness, cpv))

            for i in range(len(cases)):
                for j in range(len(cases)):
                    if cases[i][0] != cases[j][0] or cases[i][1] != cases[j][1]:
                        continue
                    else:
                        src = f"{args.src}/{cases[i][1]}"
                        agent = SarifMatchingAgent(model, src)
                        sarif = f"{args.sarif}/benchmarks/manual/[{cases[i][0]}][{cases[i][1]}][{cases[i][2]}][{cases[i][3]}].sarif"
                        crashlog = f"{args.oss_fuzz}/projects/aixcc/{cases[j][0]}/{cases[j][1]}/.aixcc/crash_logs/{cases[j][2]}/{cases[j][3]}.log"
                        patch = f"{args.oss_fuzz}/projects/aixcc/{cases[j][0]}/{cases[j][1]}/.aixcc/patches/{cases[j][2]}/{cases[j][3]}.diff"
                        expected = i == j
                        case_id = f"[{cases[i][0]}][{cases[i][1]}][{cases[i][2]}][{cases[i][3]}-{cases[j][3]}]"

                        try:
                            do(
                                agent,
                                src,
                                sarif,
                                None,
                                crashlog,
                                patch,
                                expected,
                                case_id,
                            )
                        except Exception as e:
                            logger.error(f"Error: {e}")
                            continue
