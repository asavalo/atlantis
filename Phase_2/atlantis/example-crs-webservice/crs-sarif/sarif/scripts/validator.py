import json
import os
import uuid
from pathlib import Path
from typing import Literal, get_args

import click
import openapi_client
from aim import Run
from loguru import logger
from pydantic import TypeAdapter

from crs_sarif.models.models import SarifAnalysisResult, SarifReachabilityResult
from sarif.context import SarifEnv, init_context
from sarif.models import CP, Relations_C, Relations_Java
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.validator.dynamic.replay import CoverageOSSFuzz
from sarif.validator.preprocess.info_extraction import extract_essential_info
from sarif.validator.reachability.base import BaseReachabilityAnalyser
from sarif.validator.reachability.callgraph import CallGraph
from sarif.validator.reachability.codeql import CodeQLReachabilityAnalyser
from sarif.validator.reachability.ensemble import EnsembleReachabilityAnalyser
from sarif.validator.reachability.introspector import IntrospectorReachabilityAnalyser
from sarif.validator.reachability.joern import JoernReachabilityAnalyser
from sarif.validator.reachability.sootup import SootupReachabilityAnalyser
from sarif.validator.reachability.svf import SVFReachabilityAnalyser

pass_cp = click.make_pass_decorator(CP)


@click.group()
@click.argument("cp_name", type=str)
@click.argument("language", type=click.Choice(["c", "cpp", "java"]))
@click.argument("config_path", type=click.Path(path_type=Path))
@click.pass_context
def sarif_cli(
    ctx: click.Context,
    cp_name: str,
    language: Literal["c", "cpp", "java"],
    config_path: Path,
):
    if language == "cpp":
        language = "c"

    logger.info(f"config_path: {config_path}")

    cp = CP(name=cp_name, language=language, config_path=config_path)

    init_context(cp=cp, env_mode="local", debug_mode="release")

    logger.info(f"CP: {cp}")

    ctx.obj = cp


@sarif_cli.command()
@click.argument("sarif_path", type=click.Path(path_type=Path))
@click.argument("output", type=click.Path(path_type=Path))
@click.option("--joern-cpg-path", type=click.Path(path_type=Path))
@click.option("--codeql-db-path", type=click.Path(path_type=Path))
def extract_essential_info_from_sarif(
    sarif_path: Path,
    output: Path,
    joern_cpg_path: Path | None = None,
    codeql_db_path: Path | None = None,
):
    logger.debug(f"Extracting essential info from {sarif_path}")

    if joern_cpg_path is not None:
        SarifEnv().joern_cpg_path = joern_cpg_path
    if codeql_db_path is not None:
        SarifEnv().codeql_db_path = codeql_db_path

    with open(output, "w") as f:
        f.write(
            json.dumps(
                extract_essential_info(sarif_path).model_dump_json(
                    exclude_none=True, exclude_defaults=True
                ),
                indent=4,
            )
        )

    logger.debug(f"Essential info saved to {output}")


@sarif_cli.command()
@click.argument("output", type=click.Path(path_type=Path))
@click.option(
    "--tool", type=click.Choice(["codeql", "joern", "introspector", "sootup", "svf"])
)
@click.option("--db-path", type=click.Path(path_type=Path))
@click.option("--mode", type=click.Choice(["cha", "rta", "pta"]))
@click.option(
    "--pta-algorithm",
    type=click.Choice(
        [
            "insens",
            "callsite_sensitive_1",
            "callsite_sensitive_2",
            "object_sensitive_1",
            "object_sensitive_2",
            "type_sensitive_1",
            "type_sensitive_2",
            "hybrid_object_sensitive_1",
            "hybrid_object_sensitive_2",
            "hybrid_type_sensitive_1",
            "hybrid_type_sensitive_2",
            "eagle_object_sensitive_1",
            "eagle_object_sensitive_2",
            "zipper_object_sensitive_1",
            "zipper_object_sensitive_2",
            "zipper_callsite_sensitive_1",
            "zipper_callsite_sensitive_2",
        ]
    ),
)
@pass_cp
def get_all_func_from_harness(
    cp: CP,
    output: Path,
    tool: Literal["codeql", "joern", "introspector", "sootup", "svf"] = "codeql",
    db_path: Path | None = None,
    mode: Literal["cha", "rta", "pta"] = "cha",
    pta_algorithm: Literal[
        "insens",
        "callsite_sensitive_1",
        "callsite_sensitive_2",
        "object_sensitive_1",
        "object_sensitive_2",
        "type_sensitive_1",
        "type_sensitive_2",
        "hybrid_object_sensitive_1",
        "hybrid_object_sensitive_2",
        "hybrid_type_sensitive_1",
        "hybrid_type_sensitive_2",
    ] = "insens",
):
    logger.debug(f"Getting all functions from harness for {db_path}")

    if tool == "codeql":
        cp.update_harness_path_from_codeql(db_path)
        analyser = CodeQLReachabilityAnalyser(
            cp=cp,
            db_path=db_path,
        )
    elif tool == "joern":
        analyser = JoernReachabilityAnalyser(
            cp=cp,
            cpg_path=db_path,
        )
    elif tool == "introspector":
        analyser = IntrospectorReachabilityAnalyser(
            cp=cp,
        )
    elif tool == "sootup":
        analyser = SootupReachabilityAnalyser(
            cp=cp,
            mode=mode,
            pta_algorithm=pta_algorithm,
        )
    elif tool == "svf":
        analyser = SVFReachabilityAnalyser(cp=cp, mode=mode)
    else:
        raise ValueError(f"Unsupported tool: {tool}")

    res = analyser.get_all_reachable_funcs()
    res_dict = [r.model_dump(exclude_none=True, exclude_defaults=True) for r in res]

    with open(output, "w") as f:
        f.write(json.dumps(res_dict, indent=4))

    logger.debug(f"All functions from harness saved to {output}")


@sarif_cli.command()
@click.argument("sarif_path", type=click.Path(path_type=Path))
@click.option(
    "--tool",
    type=click.Choice(["codeql", "joern", "sootup", "svf"]),
    default="codeql",
    help="Reachability analysis tool",
)
@click.option(
    "--mode",
    type=click.Choice(
        [
            "line-reachableBy",
            "func-reachableBy",
            "callgraph",
            "cha",
            "rta",
            "pta",
            "ander",
            "nander",
            "sander",
            "sfrander",
            "steens",
            "fspta",
            "vfspta",
            "type",
        ]
    ),
    default="forward",
    help="Reachability analysis mode",
)
@click.option(
    "--db-path",
    type=click.Path(path_type=Path),
    default=None,
    help="Path to CodeQL database or Joern cpg",
)
@click.option(
    "--pta-algorithm",
    type=click.Choice(
        [
            "insens",
            "callsite_sensitive_1",
            "callsite_sensitive_2",
            "object_sensitive_1",
            "object_sensitive_2",
            "type_sensitive_1",
            "type_sensitive_2",
            "hybrid_object_sensitive_1",
            "hybrid_object_sensitive_2",
            "hybrid_type_sensitive_1",
            "hybrid_type_sensitive_2",
            "eagle_object_sensitive_1",
            "eagle_object_sensitive_2",
            "zipper_object_sensitive_1",
            "zipper_object_sensitive_2",
            "zipper_callsite_sensitive_1",
            "zipper_callsite_sensitive_2",
        ]
    ),
    default="insens",
    help="Pointer analysis algorithm",
)
@click.option("--query-name", type=str, default=None)
@click.option("--exp-name", type=str, default=None)
@pass_cp
def run_reachability_analysis(
    cp: CP,
    sarif_path: Path,
    tool: Literal["codeql", "joern", "sootup", "svf"] = "codeql",
    mode: Literal[
        "callgraph",
        "line-reachableBy",
        "func-reachableBy",
        "cha",
        "rta",
        "pta",
        "ander",
        "nander",
        "sander",
        "sfrander",
        "steens",
        "fspta",
        "vfspta",
        "type",
    ] = "callgraph",
    pta_algorithm: Literal[
        "insens",
        "callsite_sensitive_1",
        "callsite_sensitive_2",
        "object_sensitive_1",
        "object_sensitive_2",
        "type_sensitive_1",
        "type_sensitive_2",
        "hybrid_object_sensitive_1",
        "hybrid_object_sensitive_2",
        "hybrid_type_sensitive_1",
        "hybrid_type_sensitive_2",
        "eagle_object_sensitive_1",
        "eagle_object_sensitive_2",
        "zipper_object_sensitive_1",
        "zipper_object_sensitive_2",
        "zipper_callsite_sensitive_1",
        "zipper_callsite_sensitive_2",
    ] = "insens",
    db_path: Path | None = None,
    query_name: str | None = None,
    exp_name: str | None = None,
):
    logger.debug(f"Running reachability analysis for {sarif_path}")

    sarif_info = extract_essential_info(sarif_path)

    # logger.debug(f"Sarif info: {sarif_info}")

    for sink_location in sarif_info.code_locations:
        if exp_name is not None:
            aim_run = Run(repo=os.getenv("AIM_SERVER_URL", None))
            aim_run.set_artifacts_uri(os.getenv("AIM_ARTIFACTS_URI", None))

            aim_run["exp_name"] = exp_name

            aim_run["cp.name"] = cp.name
            aim_run["cp.language"] = cp.language

            aim_run["sarif.path"] = sarif_path
            aim_run["sarif.name"] = sarif_path.name

            aim_run["reachability_analysis.tool"] = tool
            aim_run["reachability_analysis.mode"] = mode
            aim_run["reachability_analysis.query_name"] = query_name

            aim_run["sink_location.file.name"] = sink_location.file.name
            aim_run["sink_location.file.path"] = sink_location.file.path
            aim_run["sink_location.function.func_name"] = (
                sink_location.function.func_name
            )
            aim_run["sink_location.start_line"] = sink_location.start_line

        try:
            if tool == "codeql":
                if db_path is None:
                    raise ValueError(
                        "db_path is required for CodeQL reachability analysis"
                    )

                if mode not in list(
                    get_args(CodeQLReachabilityAnalyser.SUPPORTED_MODES)
                ):
                    raise ValueError(
                        f"Unsupported mode: {mode}. Supported modes: {CodeQLReachabilityAnalyser.SUPPORTED_MODES}"
                    )

                cp.update_harness_path_from_codeql(db_path)
                analyser = CodeQLReachabilityAnalyser(
                    cp=cp,
                    db_path=db_path,
                )
                reachable_harnesses = []
                for harness in cp.harnesses:
                    res = analyser.reachability_analysis(
                        sink_location, mode=mode, harness=harness
                    )
                    if res:
                        reachable_harnesses.append(harness)

                logger.info(f"Reachable harnesses: {reachable_harnesses}")

            # elif tool == "joern":
            #     if db_path is None:
            #         raise ValueError(
            #             "db_path (cpg_path) is required for Joern reachability analysis"
            #         )

            #     if mode not in list(get_args(JoernReachabilityAnalyser.SUPPORTED_MODES)):
            #         raise ValueError(
            #             f"Unsupported mode: {mode}. Supported modes: {JoernReachabilityAnalyser.SUPPORTED_MODES}"
            #         )

            #     analyser = JoernReachabilityAnalyser(
            #         cp=cp,
            #         cpg_path=db_path,
            #     )
            #     res = analyser.reachability_analysis(sink_location, mode=mode)

            # elif tool == "introspector":
            #     if mode not in list(
            #         get_args(IntrospectorReachabilityAnalyser.SUPPORTED_MODES)
            #     ):
            #         raise ValueError(
            #             f"Unsupported mode: {mode}. Supported modes: {IntrospectorReachabilityAnalyser.SUPPORTED_MODES}"
            #         )

            #     analyser = IntrospectorReachabilityAnalyser(
            #         cp=cp,
            #     )
            #     res = analyser.reachability_analysis(sink_location, mode=mode)

            elif tool == "sootup":
                if mode not in list(
                    get_args(SootupReachabilityAnalyser.SUPPORTED_MODES)
                ):
                    raise ValueError(
                        f"Unsupported mode: {mode}. Supported modes: {SootupReachabilityAnalyser.SUPPORTED_MODES}"
                    )

                analyser = SootupReachabilityAnalyser(
                    cp=cp,
                    mode=mode,
                    pta_algorithm=pta_algorithm,
                )
                reachable_harnesses = []
                for harness in cp.harnesses:
                    res = analyser.reachability_analysis(
                        sink_location, mode=mode, harness=harness
                    )
                    if res:
                        reachable_harnesses.append(harness.name)

            elif tool == "svf":
                if mode not in list(get_args(SVFReachabilityAnalyser.SUPPORTED_MODES)):
                    raise ValueError(
                        f"Unsupported mode: {mode}. Supported modes: {SVFReachabilityAnalyser.SUPPORTED_MODES}"
                    )

                analyser = SVFReachabilityAnalyser(cp=cp, mode=mode)
                reachable_harnesses = []
                for harness in cp.harnesses:
                    res = analyser.reachability_analysis(
                        sink_location, mode=mode, harness=harness
                    )
                    if res:
                        reachable_harnesses.append(harness)

        except Exception as e:
            logger.error(f"Error running reachability analysis: {e}")
            import traceback

            logger.error("Callstack:")
            for line in traceback.format_tb(e.__traceback__):
                logger.error(line.strip())
            if exp_name is not None:
                aim_run["reachability_analysis.result"] = "ERROR"
                aim_run["reachability_analysis.error"] = str(e)
        else:
            if exp_name is not None:
                aim_run["reachability_analysis.reachable_harnesses"] = (
                    reachable_harnesses
                )

    logger.debug(f"Reachability analysis completed.")


@sarif_cli.command()
@click.argument("sarif_path", type=click.Path(path_type=Path))
# @click.option("--tool-list", type=str, default="codeql,joern,introspector,sootup")
@click.option("--tool-list", type=str, default="codeql,joern")
@pass_cp
def run_ensemble_reachability_analysis(
    cp: CP,
    sarif_path: Path,
    # tool_list: str = "codeql,joern,introspector,sootup",
    tool_list: str = "codeql,joern",
):
    logger.debug(f"Running ensemble reachability analysis for {sarif_path}")

    sarif_info = extract_essential_info(sarif_path)

    for sink_location in sarif_info.code_locations:
        analyser = EnsembleReachabilityAnalyser(cp, tool_list=tool_list.split(","))
        res = analyser.reachability_analysis(sink_location)

        if res == True:
            logger.info(
                f"Reachable. Function {sink_location.function.func_name} can be reachable from harness"
            )
        else:
            logger.warning(
                f"Unreachable. Function {sink_location.function.func_name} cannot be reachable from harness"
            )

        logger.debug(f"Ensemble reachability analysis completed.")


@sarif_cli.command()
@click.option("--corpus-dir", type=click.Path(path_type=Path))
@click.option("--output", type=click.Path(path_type=Path))
@pass_cp
def run_coverage_replay(
    cp: CP,
    corpus_dir: Path,
    output: Path,
):
    from loguru import logger

    logger.debug(f"Running coverage replay for {cp.name}")

    coverage_runner = CoverageOSSFuzz(
        project_name=cp.name,
        harness_names=[harness.name for harness in cp.harnesses],
        language=cp.language,
        corpus_dir=corpus_dir,
    )

    fuzzer_coverage = coverage_runner.get_function_coverage()

    with open(output, "w") as f:
        f.write(fuzzer_coverage.model_dump_json(indent=4))

    logger.debug(
        f"Coverage replay completed. {len(fuzzer_coverage.func_coverages)} functions covered."
    )


@sarif_cli.command()
@click.option("--harness-name", type=str, default=None)
@click.option("--tool", type=click.Choice(["codeql", "svf", "sootup", "merge"]))
@click.option("--db-path", type=click.Path(path_type=Path))
@click.option("--svf-dot-path", type=click.Path(path_type=Path))
@click.option("--sootup-dot-path", type=click.Path(path_type=Path))
@click.option("--cp-meta-path", type=click.Path(path_type=Path))
@click.option(
    "--mode", type=click.Choice(get_args(SootupReachabilityAnalyser.SUPPORTED_MODES))
)
@click.option(
    "--pta-algorithm",
    type=click.Choice(get_args(SootupReachabilityAnalyser.SUPPORTED_PTA_ALGORITHMS)),
)
@click.option("--target-sarif-path", type=click.Path(path_type=Path), default=None)
@click.option("--function-trace-dir", type=click.Path(path_type=Path), default=None)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@click.option("--index-nodes", type=bool, default=True)
@pass_cp
def get_callgraph(
    cp: CP,
    harness_name: str | None = None,
    tool: Literal["codeql", "svf", "sootup", "merge"] = "codeql",
    db_path: Path | None = None,
    svf_dot_path: Path | None = None,
    sootup_dot_path: Path | None = None,
    cp_meta_path: Path | None = None,
    mode="cha",
    pta_algorithm="insens",
    target_sarif_path: Path | None = None,
    output: Path | None = None,
    function_trace_dir: Path | None = None,
    index_nodes: bool = True,
):
    def _update_callgraphs(
        analyser: BaseReachabilityAnalyser, function_trace_dir: Path
    ):
        files = sorted(
            function_trace_dir.glob("**/*.edges"),
            key=lambda x: x.stat().st_ctime,
            reverse=True,
        )

        logger.info(f"Found {len(files)} trace files in {function_trace_dir}")

        if cp.language in ["c", "cpp", "c++"]:
            relations_adapter = TypeAdapter(Relations_C)
        else:
            relations_adapter = TypeAdapter(Relations_Java)

        new_traces_processed = 0
        new_relations: list[Relations_C | Relations_Java] = []

        for file in files:
            try:
                with open(file, "r") as f:
                    relations_data = relations_adapter.validate_json(f.read())

                new_relations.append(relations_data)

                new_traces_processed += 1

            except Exception as e:
                logger.exception(f"Error processing trace file {file}: {e}")

        logger.info(
            f"Found {new_traces_processed} new relations in {function_trace_dir}"
        )

        updated_edges = 0
        updated_edges += analyser.update_callgraph_batch(new_relations)

        if new_traces_processed > 0:
            logger.info(
                f"Processed {new_traces_processed} new trace files for callgraph update."
            )
            logger.info(f"Updated {updated_edges} edges.")
        else:
            logger.debug("No new trace files found for callgraph update.")

    if output is None:
        output = Path(f"callgraph_{cp.name}_{tool}_{harness_name}.dot")

    if harness_name is None:
        harness = None
    elif harness_name == "all":
        harness = "all"
    else:
        harness = [h for h in cp.harnesses if h.name == harness_name][0]

    if target_sarif_path is not None:
        target_sarif_info = extract_essential_info(target_sarif_path)

        target_sink_location = target_sarif_info.code_locations[0]

    if tool == "codeql":
        cp.update_harness_path_from_codeql(db_path)
        analyser = CodeQLReachabilityAnalyser(cp=cp, db_path=db_path)

    elif tool == "svf":
        cp.update_harness_path_from_codeql(db_path)
        analyser = SVFReachabilityAnalyser(cp=cp, svf_dot_path=svf_dot_path)
    elif tool == "sootup":
        analyser = SootupReachabilityAnalyser(
            cp=cp,
            mode=mode,
            pta_algorithm=pta_algorithm,
            sootup_dot_path=sootup_dot_path,
            cpmeta_paths=[cp_meta_path],
        )
    elif tool == "merge":
        cp.update_harness_path_from_codeql(db_path)
        analyser = CodeQLReachabilityAnalyser(cp=cp, db_path=db_path)
        if cp.language == "c" or cp.language == "cpp" or cp.language == "c++":
            aux_analyser = SVFReachabilityAnalyser(cp=cp, svf_dot_path=svf_dot_path)
        elif cp.language == "java":
            aux_analyser = SootupReachabilityAnalyser(
                cp=cp,
                mode=mode,
                pta_algorithm=pta_algorithm,
                sootup_dot_path=sootup_dot_path,
                cpmeta_paths=[cp_meta_path],
            )
        else:
            raise ValueError(f"Unsupported language: {cp.language}")
    else:
        raise ValueError(f"Unsupported tool: {tool}")

    analyser.init_callgraph()
    if tool == "merge":
        aux_analyser.init_callgraph()
        analyser.whole_callgraph.merge_callgraph(aux_analyser.whole_callgraph)
        analyser.split_callgraph()

    if function_trace_dir is not None:
        _update_callgraphs(analyser, function_trace_dir)
        analyser.split_callgraph()

    if harness == "all":
        target_harnesses = cp.harnesses
    else:
        target_harnesses = [harness]

    for harness in target_harnesses:
        if target_sarif_path is None:
            callgraph = analyser.get_callgraph(harness)
        else:
            callgraph = analyser.get_target_callgraph(target_sink_location, harness)

        callgraph.print_stats()
        callgraph.dump_dot(output.with_suffix(".dot"))
        callgraph.dump_json(output.with_suffix(".json"), index_nodes=index_nodes)

    analyser.whole_callgraph.validate_nodes()

    logger.debug(f"Callgraph saved to {output.with_suffix('.json')}")


@sarif_cli.command()
@click.option("--tool", type=click.Choice(["codeql", "svf", "sootup"]))
@click.option("--db-path", type=click.Path(path_type=Path))
@click.option(
    "--mode", type=click.Choice(get_args(SootupReachabilityAnalyser.SUPPORTED_MODES))
)
@click.option(
    "--pta-algorithm",
    type=click.Choice(get_args(SootupReachabilityAnalyser.SUPPORTED_PTA_ALGORITHMS)),
)
@click.option("--output", type=click.Path(path_type=Path), default=None)
@pass_cp
def get_whole_callgraph(
    cp: CP,
    tool: Literal["codeql", "svf", "sootup"] = "codeql",
    db_path: Path | None = None,
    mode="cha",
    pta_algorithm="insens",
    output: Path | None = None,
):
    if output is None:
        output = Path(f"callgraph_{cp.name}_{tool}_whole.dot")

    if tool == "codeql":
        raise NotImplementedError("Not implemented get_whole_callgraph for CodeQL")
    elif tool == "svf":
        logger.debug(f"harnesses: {cp.harnesses}")
        analyser = SVFReachabilityAnalyser(cp=cp)
        callgraph = analyser.get_whole_callgraph()
    elif tool == "sootup":
        raise NotImplementedError("Not implemented get_whole_callgraph for Sootup")
    else:
        raise ValueError(f"Unsupported tool: {tool}")

    callgraph.print_stats()
    callgraph.dump_dot(output)

    logger.debug(f"Whole Callgraph saved to {output}")


def _get_analysis_result(
    sarif_model: AIxCCSarif,
    analyser: CodeQLReachabilityAnalyser,
) -> list[SarifAnalysisResult]:
    sarif_info = extract_essential_info(sarif_model, extract_func_name=True)
    logger.info(f"SarifInfo: {sarif_info}")
    code_locations = sarif_info.code_locations

    sarif_reachability_results = dict()
    for code_location in code_locations:
        reachable_harnesses = analyser.get_reachable_harnesses(code_location)
        logger.info(f"Reachable Harnesses: {reachable_harnesses}")

        for harness in reachable_harnesses:
            callgraph = analyser.get_target_callgraph(code_location, harness)
            callgraph.print_stats()

            if harness.name not in sarif_reachability_results:
                sarif_reachability_results[harness.name] = []

            sarif_reachability_results[harness.name].append(
                SarifReachabilityResult(
                    code_location=code_location,
                    callgraph=callgraph.to_json(),
                )
            )

    sarif_analysis_results = []
    sarif_id = uuid.uuid5(uuid.NAMESPACE_DNS, str(sarif_model.model_dump()))
    for harness_name, reachability_results in sarif_reachability_results.items():
        sarif_analysis_result = SarifAnalysisResult(
            sarif_id=sarif_id,
            rule_id=sarif_info.ruleId,
            reachable_harness=harness_name,
            reachability_results=reachability_results,
        )
        sarif_analysis_results.append(sarif_analysis_result)

    if len(sarif_analysis_results) == 0:
        logger.warning(
            f"No reachable harness found for sarif_id: {sarif_id}, code_location: {code_locations}"
        )

    return sarif_analysis_results


@sarif_cli.command()
@click.argument("sarif-path", type=click.Path(path_type=Path))
@click.option("--out-dir", type=click.Path(path_type=Path), default=None)
@click.option("--codeql-db-path", type=click.Path(path_type=Path), default=None)
@pass_cp
def get_sarif_analysis_result(
    cp: CP,
    sarif_path: Path,
    out_dir: Path | None = None,
    codeql_db_path: Path | None = None,
):
    if out_dir is None:
        out_dir = Path("./sarif_analysis_result") / cp.name
    if not out_dir.exists():
        out_dir.mkdir(parents=True, exist_ok=True)

    if codeql_db_path is not None:
        SarifEnv().codeql_db_path = codeql_db_path

    cp.update_harness_path_from_codeql(codeql_db_path)

    sarif_obj = AIxCCSarif.model_validate_json(sarif_path.read_text())
    analyser = CodeQLReachabilityAnalyser(cp=cp, db_path=codeql_db_path)
    sarif_analysis_results = _get_analysis_result(sarif_obj, analyser)

    for sarif_analysis_result in sarif_analysis_results:
        sarif_broadcast_result = openapi_client.TypesSarifAssessmentBroadcast(
            sarif_id=str(sarif_analysis_result.sarif_id),
            analysis_result=sarif_analysis_result.model_dump(mode="json"),
            fuzzer_name=sarif_analysis_result.reachable_harness,
        )

        out_path = (
            out_dir
            / cp.name
            / sarif_analysis_result.reachable_harness
            / f"{sarif_analysis_result.sarif_id}.json"
        )
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(sarif_broadcast_result.model_dump_json(indent=4))


if __name__ == "__main__":
    sarif_cli()
