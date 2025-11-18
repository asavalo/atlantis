import logging
from dataclasses import asdict

from vuli.calltree import CallTreePathFinder
from vuli.cp import CP
from vuli.joern import Joern
from vuli.struct import CodeLocation, CodePoint, VulInfo
from vuli.query_loader import QueryLoader


class PathFinder:
    def __init__(self):
        self._logger = logging.getLogger("PathFinder")

    def find(self, harness_name: str, sinks: set[int]) -> list[VulInfo]:
        paths: list[VulInfo] = self._sta(harness_name, sinks)
        sinks -= {path.sink_id for path in paths}
        paths.extend(self._cg(harness_name, sinks))
        return paths

    def _sta(self, harness_name: str, sinks: set[int]) -> list[VulInfo]:
        params = {
            "harness": str(CP().get_harness_path_by_name(harness_name)) if True else harness_name,
            "sink_ids": ",".join([str(sink) for sink in sinks])
        }
        joern_query: str = QueryLoader().get("sta", **params)
        joern_result: dict = Joern().run_query(joern_query, timeout=1200)
        joern_result: dict = {int(node): paths for node, paths in joern_result.items()}
        result: list[VulInfo] = []
        for sink_node, paths in joern_result.items():
            paths: list[list[CodePoint]] = [
                [
                    CodePoint(
                        point["filename"],
                        point["fullName"],
                        point["linNumber"],
                        point["columnNumber"],
                    )
                    for point in path
                ]
                for path in paths
            ]
            paths: list[list[CodePoint]] = [
                self._erase_duplicates(path) for path in paths
            ]
            paths: list[VulInfo] = [
                VulInfo(
                    harness_name,
                    sink_node,
                    path,
                    CodeLocation(path[-1].path, path[-1].line, path[-1].column),
                )
                for path in paths
                if len(path) > 0
            ]
            result.extend(paths)
        self._logger.info(
            f"Static Taint Analysis found {len(result)} Paths [harness={harness_name}]"
        )
        return result

    def _cg(self, harness_name: str, sinks: set[int]) -> list[VulInfo]:
        params = {
            "harness": str(CP().get_harness_path_by_name(harness_name)) if True else harness_name,
            "sink_ids": ",".join([str(sink) for sink in sinks])
        }
        joern_query: str = QueryLoader().get("cg", **params)
        joern_result: dict = Joern().run_query(joern_query)
        srcs: set[int] = set(joern_result.get("srcs", []))
        dst_table: dict[int, list[int]] = {
            int(key): value for key, value in joern_result.get("dst_table", {}).items()
        }
        dsts: set[int] = set(dst_table.keys())

        finder = CallTreePathFinder()
        result: list[VulInfo] = []
        covered_sinks: set[int] = set()
        for src in srcs:
            for dst in dsts:
                path: list[int] = finder.find_path(src, dst)
                if path is None or len(path) < 1:
                    continue
                related_sinks: set[int] = set(dst_table.get(path[-1], []))
                if len(related_sinks) == 0:
                    continue
                joern_query: str = f"""
def firstNode(method: Method): CfgNode = {{
    val node: CfgNode = method.cfgFirst.head
    node.lineNumber match {{
        case Some(x) => node
        case _ => method.call.map(x => (x, x.lineNumber)).collect{{case (a, Some(b)) => (a, b)}}.sortBy(_._2).head._1
    }}
}}
cpg.ids({",".join([str(x) for x in path])})
    .collect{{case x: Method => x}}
    .map(firstNode)
    .map(x => (x.method.filename, x.method.fullName, x.lineNumber, x.columnNumber.getOrElse(-1)))
    .collect{{case (a, b, Some(c), d) => (a, b, c, d)}}
    .map(x => Map(
        "path" -> x._1,
        "method" -> x._2,
        "line" -> x._3,
        "column" -> x._4
    )).l"""
                joern_path: list[dict] = Joern().run_query(joern_query)
                covered_sinks |= related_sinks
                joern_query: str = f"""
cpg.ids({",".join([str(sink) for sink in related_sinks])})
    .collect{{case x: CfgNode => x}}
    .map(x => (x.id, x.method.filename, x.lineNumber, x.columnNumber.getOrElse(-1)))
    .collect{{case (a, b, Some(c), d) => (a, b, c, d)}}
    .map(x => (x._1, s"${{x._2}}:${{x._3}}:${{x._4}}"))
    .toMap
"""
                joern_result: list[str] = Joern().run_query(joern_query)
                for sink in related_sinks:
                    loc: str = joern_result.get(str(sink), "")
                    if len(loc) == 0:
                        continue

                    v_point = CodeLocation.create(loc)
                    v_path = [
                        CodePoint(
                            item["path"],
                            item["method"],
                            item["line"],
                            item["column"],
                        )
                        for item in joern_path
                        + [
                            {
                                **asdict(v_point),
                                "method": joern_path[-1]["method"],
                            }
                        ]
                    ]
                    v_path: list[CodePoint] = self._erase_duplicates(v_path)
                    v_info = VulInfo(harness_name, sink, v_path, v_point)
                    result.append(v_info)
        self._logger.info(
            f"Call-Graph Analyzer found {len(result)} Paths [harness={harness_name}]"
        )
        return result

    def _erase_duplicates(self, path: list[CodePoint]) -> list[CodePoint]:
        if len(path) == 0:
            return path

        real_path: list[CodePoint] = [path[-1]]
        for point in reversed(path[0:-1]):
            if real_path[-1].path != point.path or real_path[-1].line != point.line:
                real_path.append(point)
        real_path.reverse()
        return real_path
