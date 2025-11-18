import json
import logging
from pathlib import Path, PurePosixPath

from vuli.common.setting import Setting
from vuli.joern import Joern
from vuli.path_manager import Status
from vuli.scan import Origin, SinkManager, SinkProperty
from vuli.struct import CodeLocation
from vuli.query_loader import QueryLoader

logger = logging.getLogger(__name__)


class SarifLog:
    def __init__(self, sarif_path: Path):
        self.mode = Setting().mode
        self.test_data = self._load_test_data(sarif_path)
        self.sanitizers = []
        # self._set_sanitizers()
        self.sinks: dict[str, set[int]] = dict()
        self.sinks_for_storage = {}

    # def _set_sanitizers(self):
    #     runs = self.test_data.get("runs", [])
    #     for run in runs:
    #         rules = run.get("tool", None).get("driver", None).get("rules", None)
    #         for rule in rules:
    #             if rule not in self.sanitizers:
    #                 self.sanitizers.append(rule["id"])

    def _load_test_data(self, sarif_path: Path):
        with open(sarif_path) as f:
            return json.load(f)

    def extract(self):
        runs = self.test_data.get("runs", [])
        if not runs:
            return {}

        for run in runs:
            results = run.get("results", [])
            if not results:
                continue

            for result in results:
                self._process_result(result)

        result: dict[int, SinkProperty] = {
            sink: SinkProperty(
                bug_types={name}, origins={Origin.FROM_SARIF}, status=Status.UNKNOWN.value
            )
            for name, sinks in self.sinks.items()
            for sink in sinks
        }
        SinkManager().add_batch(result)

    def _process_result(self, result):
        v_type = result.get("ruleId")
        if not v_type:
            return
        if v_type not in self.sanitizers:
            self.sanitizers.append(v_type)
            self.sinks_for_storage[v_type] = set()

        for loc in result.get("locations", []):
            self._process_location(loc, v_type)

    def _process_location(self, loc, v_type):
        phys_loc = loc.get("physicalLocation", {})
        if not phys_loc:
            logger.debug(f"Missing physical location: {loc}")
            return

        uri, start_line, start_column = self._extract_location_info(phys_loc)
        if not uri or start_line == -1:
            logger.info(f"Incomplete physical location: {loc}")
            return
        
        uri = PurePosixPath(uri.lstrip('/'))
        parts = uri.parts
    
        for i in range(len(parts)):
            trimmed_uri = PurePosixPath(*parts[i:]).as_posix()
            joern_query = self._build_joern_query(trimmed_uri, start_line, start_column)
            if joern_query:
                code_location = CodeLocation(trimmed_uri, start_line, start_column)
                if self._process_joern_query(joern_query, v_type, code_location):
                    return

        code_location = CodeLocation(uri, start_line, start_column)
        logger.debug(
            f"Failed to locate by physical location: {code_location.to_dict()}"
        )

    def _extract_location_info(self, phys_loc):
        uri = phys_loc.get("artifactLocation", {}).get("uri", "")
        region = phys_loc.get("region", {})
        start_line = region.get("startLine", -1)
        start_column = region.get("startColumn", -1)
        return uri, start_line, start_column

    def _build_joern_query(self, uri, start_line, start_column):
        params = {
            "uri": uri,
            "start_line": start_line,
            "start_column": start_column
        }
        joern_query: str = QueryLoader().get("sink_from_sarif", **params)
        return joern_query

    def _process_joern_query(self, joern_query, v_type, code_location: CodeLocation) -> bool:
        joern_result = Joern().run_query(joern_query)
        if joern_result:
            sink_node = int(joern_result[0])
            self.sinks.setdefault(v_type, set()).add(sink_node)
            self.sinks_for_storage[v_type].add(code_location)
            return True
        return False

    def _get_sinks_from_storage(self):
        return {
            v_type: {sink for sink in sink_nodes}
            for v_type, sink_nodes in self.sinks_for_storage.items()
            if sink_nodes
        }
