import os
import subprocess
from tempfile import TemporaryDirectory
from collections import defaultdict
from tracer.model import Relation, Relations, Caller, Callee, CallState, MethodInfo


class JazzerTracer:
    def __init__(self, workdir: str) -> None:
        self.workdir = workdir
        self.raw_trace_data: list[str] | None = None

    def _trim_trace_data(self, trace_data: list[str]) -> list[str]:
        result = list()
        for func in trace_data:
            if not result:
                result.append(func)
                continue
            if result[-1] != func:
                result.append(func)

        return result

    def _parse_caller_raw_info(self, raw_info: str) -> Caller:
        return Caller(
            file=raw_info.split(":")[0],
            class_name=raw_info.split(":")[2],
            method_name=raw_info.split(":")[3],
            prototype=raw_info.split(":")[4],
        )

    def _parse_callee_raw_info(self, raw_info: str) -> Callee:
        return Callee(
            file=raw_info.split(":")[0],
            class_name=raw_info.split(":")[1],
            method_name=raw_info.split(":")[2],
            prototype=raw_info.split(":")[3],
        )

    def _parse_callstate_raw_info(self, raw_info: str, callee: Callee) -> CallState:
        return CallState(
            file=raw_info.split(":")[0],
            line=int(raw_info.split(":")[1], 10),
            callee=callee,
        )

    def parse_raw_trace_data_for_edges(self) -> Relations:
        # NOTE: Raw trace data is like:
        # caller-filename:caller-lineno:caller-class-name:caller-method-name
        # ,
        # callee-filename:callee-prototype:callee-class-name:callee-method-name
        trace_data = self._trim_trace_data(self.raw_trace_data)
        relations = Relations()
        caller_map = {}  # Dictionary to map caller to relation index

        for line in trace_data:
            thread_id_str, callstate_raw_info, callee_raw_info = line.split(",")
            
            caller = self._parse_caller_raw_info(callstate_raw_info)
            callee = self._parse_callee_raw_info(callee_raw_info)
            callstate = self._parse_callstate_raw_info(callstate_raw_info, callee)

            if caller in caller_map:
                # Caller already exists in our relations
                relation_idx = caller_map[caller]
                relation = relations[relation_idx]

                # Check if callstate already exists
                if not callstate in relation.callees:
                    relation.callees.append(callstate)
            else:
                # New caller
                relations.append(Relation(caller=caller, callees=[callstate]))
                caller_map[caller] = len(relations) - 1

        return relations

    def parse_raw_data_for_trace(self) -> dict[int, Relations]:
        calltraces: dict[int, Relations] = defaultdict(Relations)

        for line in self.raw_trace_data:
            thread_id_str, callstate_raw_info, callee_raw_info = line.split(",")
            thread_id = int(thread_id_str, 10)
            caller = self._parse_caller_raw_info(callstate_raw_info)
            callee = self._parse_callee_raw_info(callee_raw_info)
            callstate = self._parse_callstate_raw_info(callstate_raw_info, callee)

            # TODO: Can we parse untracked function information?
            calltraces[thread_id].append(Relation(caller=caller, callees=[callstate]))

        return calltraces

    def trace(self, harness: str, input_data: bytes) -> Relations:
        harness_path = os.path.join(self.workdir, harness)

        with TemporaryDirectory() as temp_dir:
            temp_input_path = os.path.join(temp_dir, "input")
            temp_trace_output_path = os.path.join(temp_dir, "trace.out")

            with open(temp_input_path, "wb") as f:
                f.write(input_data)

            cmd = [
                harness_path,
                "-runs=1",
                f"--trace_dump={temp_trace_output_path}",
                temp_input_path,
            ]
            subprocess.run(
                cmd,
                # capture_output=True,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
            )

            with open(temp_trace_output_path, "r") as f:
                self.raw_trace_data = [line.replace("\n", "") for line in f.readlines()]
