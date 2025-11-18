from pathlib import Path
from typing import Literal

from loguru import logger

from sarif.context import SarifEnv
from sarif.models import CP, CodeLocation, Function, SarifInfo
from sarif.tools.joern.server import JoernServer
from sarif.validator.reachability.base import BaseReachabilityAnalyser


class JoernReachabilityAnalyser(BaseReachabilityAnalyser):
    SUPPORTED_MODES = Literal[
        "line-reachableBy", "func-reachableBy", "callgraph", "backward"
    ]

    def __init__(self, cp: CP, *, cpg_path: Path | None = None):
        super().__init__(cp)

        if cpg_path is None:
            cpg_path = SarifEnv().joern_cpg_path

        self.cpg_path = cpg_path
        self.server = JoernServer(cpg_path)

    @staticmethod
    def _check_reachable(query_res: dict, *, code_location: CodeLocation) -> bool:
        if query_res:
            logger.info(
                f"Reachable. Location {code_location.file.name}:{code_location.start_line} can be reachable from harness"
            )
            return True
        else:
            logger.warning(
                f"Unreachable. Location {code_location.file.name}:{code_location.start_line} cannot be reachable from harness"
            )
            return False

    def _line_reachable_by_reachability_analysis(
        self, sink_location: CodeLocation
    ) -> bool:
        query = f"""\
            def sink = cpg
                    .file
                    .filter {{ _.name.endsWith("{sink_location.file.name}") }}
                    .ast
                    .lineNumber({sink_location.start_line})
                    .isIdentifier
            def source = cpg
                        .file
                        .filter {{ f => {" || ".join('f.name.endsWith("{}")'.format(harness.path.name) for harness in self.cp.harnesses)} }}
                        .ast
                        .isIdentifier
            sink.reachableByFlows(source).toList.size
        """

        result = self.server.query_json(query)

        return self._check_reachable(result, code_location=sink_location)

    def _func_reachable_by_reachability_analysis(
        self, sink_location: CodeLocation
    ) -> bool:
        query = f"""\
            def sink = cpg
                    .file
                    .filter {{ _.name.endsWith("{sink_location.file.name}") }}
                    .method
                    .filter {{ m =>
                            m.lineNumber.exists( _ <= {sink_location.start_line} ) &&
                            m.lineNumberEnd.exists( _ >= {sink_location.start_line} ) &&
                            m.code != "<global>"
                    }}
                    .ast
                    .isIdentifier
            def source = cpg
                        .file
                        .filter {{ f => {" || ".join('f.name.endsWith("{}")'.format(harness.path.name) for harness in self.cp.harnesses)} }}
                        .ast
                        .isIdentifier
            sink.reachableByFlows(source).toList.size
        """

        result = self.server.query_json(query)

        return self._check_reachable(result, code_location=sink_location)

    def _callgraph_reachability_analysis(self, sink_location: CodeLocation) -> bool:

        sinks = list(
            map(
                tuple,
                self.server.query_json(
                    f"""\
                cpg
                .method
                .filter {{ m =>
                    m.filename.endsWith("{sink_location.file.name}") &&
                    m.lineNumber.exists( _ <= {sink_location.start_line} ) &&
                    m.lineNumberEnd.exists( _ >= {sink_location.start_line} ) &&
                    m.code != "<global>"
                }}
                .map {{ m =>
                    (m.filename, m.lineNumber, m.name).toList
                }}
                .toJson
            """
                ),
            )
        )

        sources = list(
            map(
                tuple,
                self.server.query_json(
                    f"""\
                cpg
                .method
                .filter {{ m =>
                    {" || ".join(f'm.filename.endsWith("{harness.path.name}")' for harness in self.cp.harnesses)} &&
                    m.code != "<global>"
                }}
                .map {{ m =>
                    (m.filename, m.lineNumber, m.name).toList
                }}
                .toJson
            """
                ),
            )
        )

        processed = set(sources.copy())

        # logger.debug(f"sinks: {sinks}")

        reached = True
        while sources:
            filename, lineNumber, name = sources.pop()
            target = (filename, lineNumber, name)

            if target in sinks:
                break
            logger.debug(f"target: {target}")

            callees = (
                list(
                    map(
                        tuple,
                        self.server.query_json(
                            f"""\
                    cpg
                    .method
                    .filter {{ m =>
                        m.filename == "{filename}" &&
                        m.lineNumber.exists( _ == {lineNumber} ) &&
                        m.name == "{name}"
                    }}
                    .ast
                    .isCall
                    .filter {{ ! _.name.startsWith("<operator>") }}
                    .name
                    .map {{ n => cpg.method.name(n) }}
                    .flatten
                    .dedup
                    .filter {{ m =>
                        m.filename != "<empty>"
                    }}
                    .map {{ m =>
                        (m.filename, m.lineNumber, m.name).toList
                    }}
                    .toJson
                """
                        ),
                    )
                )
                + list(
                    map(
                        tuple,
                        self.server.query_json(
                            f"""
                    cpg
                    .method
                    .filter {{ m =>
                        m.filename == "{filename}" &&
                        m.lineNumber.exists( _ == {lineNumber} ) &&
                        m.name == "{name}"
                    }}
                    .ast
                    .isCall
                    .filter {{ _.name == "<operator>.pointerCall" }}
                    .map {{ _.astChildren.head.code }}
                    .map {{ c =>
                        cpg
                        .assignment
                        .filter {{ _.target.code == c }}
                        .source
                        .label("METHOD_REF")
                        .cast[nodes.MethodRef]
                        .code
                    }}
                    .flatten
                    .dedup
                    .map {{ n => cpg.method.name(n) }}
                    .flatten
                    .dedup
                    .filter {{ m =>
                        m.filename != "<empty>"
                    }}
                    .map {{ m =>
                        (m.filename, m.lineNumber, m.name).toList
                    }}
                    .toJson
                """
                        ),
                    )
                )
            )

            for callee in callees:
                # logger.debug(f"callee: {callee}")
                if callee in processed:
                    continue
                # logger.debug(f"added: {callee}")
                processed.add(callee)
                sources.append(callee)

        else:
            reached = False

        if reached:
            logger.info(
                f"Reachable. Location {sink_location.file.name}:{sink_location.start_line} can be reachable from harness"
            )
        else:
            logger.warning(
                f"Unreachable. Location {sink_location.file.name}:{sink_location.start_line} cannot be reachable from harness"
            )

        return reached

    def _backward_reachability_analysis(self, sink_location: CodeLocation) -> bool:
        sinks = list(
            map(
                tuple,
                self.server.query_json(
                    f"""\
                cpg
                .method
                .filter {{ m =>
                    m.filename.endsWith("{sink_location.file.name}") &&
                    m.lineNumber.exists( _ <= {sink_location.start_line} ) &&
                    m.lineNumberEnd.exists( _ >= {sink_location.start_line} ) &&
                    m.code != "<global>"
                }}
                .map {{ m =>
                    (m.filename, m.lineNumber, m.fullName).toList
                }}
                .toJson
            """
                ),
            )
        )

        sources = list(
            map(
                tuple,
                self.server.query_json(
                    f"""\
                cpg
                .method
                .filter {{ m =>
                    {" || ".join(f'm.filename.endsWith("{harness.path.name}")' for harness in self.cp.harnesses)} &&
                    m.code != "<global>"
                }}
                .map {{ m =>
                    (m.filename, m.lineNumber, m.fullName).toList
                }}
                .toJson
            """
                ),
            )
        )

        processed = set(sinks.copy())
        reached = True
        while sinks:
            filename, lineNumber, fullName = sinks.pop()
            target = (filename, lineNumber, fullName)
            logger.debug(f"target: {target}")

            if target in sources:
                break

            callers = list(
                map(
                    tuple,
                    self.server.query_json(
                        f"""\
                    cpg
                    .method
                    .filter {{ m =>
                        m.filename == "{filename}" &&
                        m.lineNumber.exists( _ == {lineNumber} ) &&
                        m.fullName == "{fullName}"
                    }}
                    .callIn
                    .method
                    .dedup
                    .map {{ m =>
                        (m.filename, m.lineNumber, m.fullName).toList
                    }}
                    .toJson
                """
                    ),
                )
            )

            for caller in callers:
                if caller in processed:
                    continue
                processed.add(caller)
                sinks.append(caller)
        else:
            reached = False

        if reached:
            logger.info(
                f"Reachable. Location {sink_location.file.name}:{sink_location.start_line} can be reachable from harness"
            )
        else:
            logger.warning(
                f"Unreachable. Location {sink_location.file.name}:{sink_location.start_line} cannot be reachable from harness"
            )

        return reached

    def get_all_reachable_funcs(self) -> list[Function]:
        raise NotImplementedError

    def reachability_analysis(
        self,
        sink_location: CodeLocation,
        *,
        mode: SUPPORTED_MODES | None = None,
    ) -> bool:
        if mode is None:
            mode = "line-reachableBy"

        if sink_location.start_line == 0:
            raise ValueError("Start line is required in JoernReachabilityAnalyser")

        match mode:
            case "line-reachableBy":
                return self._line_reachable_by_reachability_analysis(sink_location)
            case "func-reachableBy":
                return self._func_reachable_by_reachability_analysis(sink_location)
            case "callgraph":
                return self._callgraph_reachability_analysis(sink_location)
            case "backward":
                return self._backward_reachability_analysis(sink_location)
