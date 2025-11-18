import json
import logging
import sqlite3
from functools import reduce
from pathlib import Path
from typing import Optional

import networkx as nx
from vuli.common.singleton import Singleton
from vuli.cp import CP
from vuli.joern import Joern
from vuli.query_loader import QueryLoader


class CallTree(metaclass=Singleton):

    def __init__(self):
        self._logger = logging.getLogger("CallTree")
        self._conn: Optional[Path] = None
        self._updated: bool = False
        self._callee_tree = QueryLoader().get("callee_tree")

    def build(self, harness_names: list[str], call_depth: int = 30) -> None:
        """
        Build CallTree using harness_names as roots

        Args:
            harness_names: Harness Names. This should be match to class name of
                harness where fuzzerTestOneInput method is defined.
            call_depth: Call Depth. This is related to resource usage and speed
                of algorithms that are works on the built call tree.
                Default is set to 30, which is enough to cover all
                vulnerabilities we prepared to test.

        """
        self._logger.info(
            f"Building from harnesses: {",".join([harness_name for harness_name in harness_names])}"
        )
        params = {
            "call_depth": call_depth,
            "visited_ids": ",".join([f"{x}L" for x in self._get_visited()]),
            "harness_list": ",".join([
                f"\"^.*{str(CP().get_harness_path_by_name(harness_name))}\""
                for harness_name in harness_names
            ]) if True else ",".join([
                f"\"{harness_name}\"" for harness_name in harness_names
            ])
        }
        joern_query: str = f"""
{self._callee_tree}
{QueryLoader().get("build_callee_tree", **params)}
"""
        joern_result: list[dict] = Joern().run_query(joern_query, 1200)
        self._update(joern_result)

    def close(self) -> None:
        self._logger.info("Close CallTree")
        if self._conn is not None:
            self._conn.close()
        self._conn = None

    def insert(self, src: int, dsts: set[int]) -> None:
        self._logger.info(f"Insert {src}->{",".join([str(x) for x in dsts])}")
        add_callees: set[int] = self._update_each(src, dsts)
        joern_query: str = f"""
{self._callee_tree}
val visited: mutable.Set[Long] = List({",".join([f"{x}L" for x in self._get_visited()])}).to(mutable.Set)
cpg.ids({",".join([str(x) for x in add_callees])})
    .collect{{case x: Method => x}}
    .flatMap(x => getCalleeTree(x, visited, 30))
    .l"""
        self._logger.info(
            f"Building from edges: {",".join([str(x) for x in add_callees])}"
        )
        result: list[dict] = Joern().run_query(joern_query, timeout=1200)
        self._update(result)

    def open(self, path: Path) -> None:
        self.close()
        self._logger.info("Open CallTree")
        self._path = path
        self._conn = sqlite3.connect(str(self._path))
        self._setup_tables()

    def get(self) -> dict:
        cursor = self._conn.cursor()
        cursor.execute("SELECT id, callees FROM callgraph")
        rows = cursor.fetchall()
        return {row[0]: json.loads(row[1]) for row in rows}

    def _get_visited(self) -> list[int]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT id FROM callgraph")
        return [int(x[0]) for x in cursor.fetchall()]

    def _setup_tables(self):
        self._logger.info("Setup Table")
        cursor = self._conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS callgraph (
                id TEXT PRIMARY KEY,
                callees TEXT
            )
        """
        )
        self._conn.commit()

    def _update(self, result: list[dict]) -> None:
        cnt: int = reduce(
            lambda y, x: y + len(self._update_each(x["id"], set(x["callees"]))),
            result,
            0,
        )
        if cnt > 0:
            self._conn.commit()
            self._updated = True

    def _update_each(self, caller: int, callees: set[int]) -> set[int]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT callees FROM callgraph WHERE id = ?", (str(caller),))
        prev_data: dict = cursor.fetchone()
        prev_callees: set[int] = (
            set() if prev_data is None else set(json.loads(prev_data[0]))
        )
        add_callees: set[int] = callees - prev_callees
        if len(add_callees) == 0 and len(prev_callees) != 0:
            return set()
        next_data: dict = json.dumps(list(add_callees | prev_callees))
        cursor.execute(
            "INSERT OR REPLACE INTO callgraph (id, callees) VALUES (?, ?)",
            (caller, next_data),
        )
        self._logger.info(
            f"CallGraph Update {caller} -> {",".join([str(x) for x in add_callees])}"
        )
        return add_callees


class CallTreePathFinder:
    def __init__(self):
        self._logger = logging.getLogger("CallTreePathFinder")
        self._G = nx.DiGraph()
        for caller, callees in CallTree().get().items():
            nodes: list[int] = [int(x) for x in [caller] + callees]
            [self._G.add_node(x) for x in nodes if x not in self._G]
            [self._G.add_edge(int(caller), x) for x in callees]

    def find_path(self, src: int, dst: int) -> Optional[list[int]]:
        if src not in self._G or dst not in self._G:
            return None

        if not nx.has_path(self._G, src, dst):
            return None

        return nx.shortest_path(self._G, src, dst)
