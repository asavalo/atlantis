import json
from pathlib import Path

from loguru import logger

from sarif.context import SarifCacheManager, SarifEnv, SarifServerManager
from sarif.models import (
    CodeFlow,
    CodeLocation,
    File,
    Function,
    RelatedLocation,
    SarifInfo,
    ThreadFlow,
    ThreadFlowLocation,
)
from sarif.sarif_model import (
    AixccEnhancedStaticAnalysisResultsFormatSarifVersion210JsonSchema as AIxCCSarif,
)
from sarif.tools.codeql.queries import get_function_by_line
from sarif.utils.cache import cache_function


class NoFunctionFoundError(Exception): ...


class MultipleFunctionsFoundError(Exception): ...


def _get_file_short_name(full_name: str) -> str:
    return full_name.split("/")[-1]


def _get_func_short_name(full_name: str) -> str:
    if "." in full_name:
        # Java
        return full_name.split(".")[-1]
    else:
        # C
        return full_name.split("/")[-1]


def _get_func_name_by_line(
    file_path: str, start_line: int, end_line: int
) -> tuple[str, str]:
    # try:
    #     return __get_func_by_line_joern(file_path, line_number, line_number)
    # except (NoFunctionFoundError, MultipleFunctionsFoundError) as e:
    #     logger.warning(f"Getting function name by line using joern failed: {e}")

    try:
        return __get_func_by_line_codeql(file_path, start_line, end_line)
    except (NoFunctionFoundError, MultipleFunctionsFoundError) as e:
        logger.warning(f"Getting function name by line using codeql failed: {e}")

    raise NoFunctionFoundError(
        f"No function found at line {start_line}:{end_line} in file {file_path}"
    )


def _safe_parse_codeql_res(res: dict) -> dict:
    for key in res.keys():
        match key:
            case (
                "func" | " file" | "file_abs" | "class_name" | "start_line" | "end_line"
            ):
                if res[key] == "UNKNOWN":
                    logger.warning(f"res: {res}")
                    raise ValueError(f"Missing required field: {key}")
            case "sig" | "method_desc":
                if res[key] == "UNKNOWN":
                    res[key] = ""
    return res


@cache_function(SarifCacheManager().memory)
def __get_func_by_line_codeql(file_path: str, start_line: int, end_line: int):
    query = get_function_by_line(SarifEnv().cp.language)

    query_res = query.run(
        database=SarifEnv().codeql_db_path,
        params={"file_path": file_path, "start_line": start_line, "end_line": end_line},
    )

    res = query_res.parse()

    if len(res) == 0:
        raise NoFunctionFoundError(
            f"No function found at line {start_line}:{end_line} in file {file_path}"
        )

    return [_safe_parse_codeql_res(r) for r in res]


def __get_func_by_line_joern(
    file_path: str, start_line: int, end_line: int
) -> tuple[str, str, int, int]:
    if file_path.startswith("/src/"):
        file_path = file_path[5:]

    res = list(
        map(
            tuple,
            SarifServerManager().joern_server.query_json(
                f"""\
                cpg
                .method
                .filter {{ m =>
                    m.filename.endsWith("{file_path}") &&
                    m.lineNumber.exists( _ <= {end_line} ) &&
                    m.lineNumberEnd.exists( _ >= {start_line} ) &&
                    m.code != "<global>"
                }}
                .map {{ m =>
                    (m.filename, m.name, m.lineNumber, m.lineNumberEnd, m.className.orElse(null), m.signature.orElse(null), m.methodDesc.orElse(null)).toList
                }}
                .toJson
            """
            ),
        )
    )

    if len(res) == 0:
        raise NoFunctionFoundError(
            f"No function found at line {start_line}:{end_line} in file {file_path}"
        )
    elif len(res) > 1:
        raise MultipleFunctionsFoundError(
            f"Found multiple functions at line {start_line}:{end_line} in file {file_path}"
        )

    # (filename, func_name, start_line, end_line)
    return "/src/" + res[0][0], res[0][1], int(res[0][2]), int(res[0][3])


def extract_essential_info(
    sarif_res: AIxCCSarif | Path, extract_func_name: bool = True
) -> SarifInfo:
    if isinstance(sarif_res, Path):
        with open(sarif_res) as f:
            sarif_json = json.load(f)

        sarif_model = AIxCCSarif.model_validate(sarif_json)

    else:
        sarif_model = sarif_res

    assert len(sarif_model.runs) == 1, "Only one run is supported"
    assert len(sarif_model.runs[0].results) == 1, "Only one result is supported"
    assert (
        len(sarif_model.runs[0].results[0].locations) >= 1
    ), "At least one location is required."

    res = sarif_model.runs[0].results[0]

    code_locations = []
    for location in res.locations:
        file_path = location.physicalLocation.root.artifactLocation.uri

        start_line = location.physicalLocation.root.region.root.startLine
        start_column = getattr(
            location.physicalLocation.root.region.root, "startColumn", None
        )
        end_line = getattr(location.physicalLocation.root.region.root, "endLine", None)
        end_column = getattr(
            location.physicalLocation.root.region.root, "endColumn", None
        )

        # assert file_path is not None, "File path is not found"
        # TODO: start_line can be optional, but in that case charOffset or byteOffset must be provided.
        # TODO: Need to consider whether to handle this case.
        # assert start_line is not None, "Start line is not found"

        if extract_func_name:
            try:
                query_res = _get_func_name_by_line(
                    file_path,
                    start_line,
                    end_line if end_line is not None else start_line,
                )
            except NoFunctionFoundError:
                logger.warning(
                    f"It seems that there is no function name at {file_path}:{start_line}:{end_line}"
                )
            except MultipleFunctionsFoundError as e:
                logger.warning(
                    f"It seems that there are multiple functions at {file_path}:{start_line}:{end_line}\n"
                    f"{e}"
                )
            else:
                for func in query_res:
                    sig = func["sig"] if "sig" in func else None
                    class_name = func["class_name"] if "class_name" in func else None
                    method_desc = func["method_desc"] if "method_desc" in func else None

                    code_locations.append(
                        CodeLocation(
                            file=File(
                                name=func["file_abs"],
                                path=Path(func["file_abs"]),
                            ),
                            function=Function(
                                func_name=func["func"],
                                file_name=func["file_abs"],
                                class_name=class_name,
                                func_sig=sig,
                                method_desc=method_desc,
                                start_line=func["start_line"],
                                end_line=func["end_line"],
                            ),
                            start_line=start_line,
                            start_column=start_column,
                            end_line=end_line,
                            end_column=end_column,
                        )
                    )

    # (Optional) extract additional information
    # it could be seperated to another function(e.g. extract_additional_info)

    # codeFlows
    code_flows = []
    try:
        for code_flow in res.codeFlows:
            thread_flows = []
            for thread_flow in code_flow.threadFlows:
                thread_flow_locations = []
                for thread_flow_location in thread_flow.locations:
                    thread_flow_locations.append(
                        ThreadFlowLocation(
                            loc_file_full_name=thread_flow_location.location.physicalLocation.root.artifactLocation.uri,
                            loc_file_short_name=_get_file_short_name(
                                thread_flow_location.location.physicalLocation.root.artifactLocation.uri
                            ),
                            loc_line=thread_flow_location.location.physicalLocation.root.region.root.startLine,
                            message=thread_flow_location.location.message.root.text,
                        )
                    )
                thread_flows.append(
                    ThreadFlow(thread_flow_locations=thread_flow_locations)
                )
            code_flows.append(CodeFlow(thread_flows=thread_flows))
    except Exception as e:
        logger.warning(f"Failed to extract codeFlows (threadFlows): {e}")
        code_flows = []

    # relatedLocations
    related_locations = []
    try:
        if hasattr(res, "relatedLocations") and res.relatedLocations:
            for rl in res.relatedLocations:
                related_locations.append(
                    RelatedLocation(
                        loc_file_full_name=rl.physicalLocation.root.artifactLocation.uri,
                        loc_file_short_name=_get_file_short_name(
                            rl.physicalLocation.root.artifactLocation.uri
                        ),
                        loc_line=rl.physicalLocation.root.region.root.startLine,
                        message=rl.message.root.text,
                    )
                )
    except Exception as e:
        logger.warning(f"Failed to extract relatedLocations. Ignoring. {e}")
        related_locations = []

    return SarifInfo(
        ruleId=res.ruleId,
        message=res.message.root.text,
        code_locations=code_locations,
        related_locations=related_locations,
        code_flows=code_flows,
    )
