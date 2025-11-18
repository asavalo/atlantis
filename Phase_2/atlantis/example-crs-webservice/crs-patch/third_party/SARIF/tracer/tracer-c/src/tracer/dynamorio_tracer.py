import os
import subprocess
import shutil
import random
import tarfile

from tempfile import TemporaryDirectory
from collections import defaultdict

from tracer.model import Relation, Relations, Caller, Callee, CallState, FunctionInfo


class DynamoRIOTracer:
    def __init__(
        self,
        harness_dir: str,
        copy: bool = False,
        dynamorio_home_path: str | None = None,
        dynamorio_plugin_path: str | None = None,
    ) -> None:
        if not copy:
            self.fuzzing_resource_dir = os.path.abspath(
                os.getenv("MULTILANG_BUILD_DIR")
            )
        self.workdir = self._initialize_trace_workdir(harness_dir, copy=copy)
        if dynamorio_home_path == None:
            dynamorio_home = os.path.abspath(
                os.getenv("CRS_SARIF_TRACER_DYNAMORIO_HOME")
            )
        else:
            dynamorio_home = dynamorio_home_path

        self.dynamorio_engine_path = os.path.join(dynamorio_home, "bin64", "drrun")

        if dynamorio_plugin_path == None:
            self.dynamorio_plugin_path = os.getenv(
                "CRS_SARIF_TRACER_FUNCTION_TRACER_PLUGIN"
            )
        else:
            self.dynamorio_plugin_path = dynamorio_plugin_path

        self._global_callstack: list[FunctionInfo, int] = list()
        self.raw_trace_data: list[str] | None = None

    def _initialize_trace_workdir(self, harness_dir: str, copy: bool) -> str:
        tempdir = "".join(["%02x" % random.randint(0, 256) for _ in range(32)])
        tempdir = os.path.join("/tmp", tempdir)

        # shutil.copytree(harness_dir, tempdir)

        if copy:
            if os.path.exists(tempdir):
                shutil.rmtree(tempdir)
            shutil.copytree(harness_dir, tempdir)
            return tempdir

        if not os.path.exists(tempdir):
            os.makedirs(tempdir)

        with tarfile.open(
            os.path.join(self.fuzzing_resource_dir, "fuzzers.tar.gz"), "r:*"
        ) as tar:
            tar.extractall(path=tempdir)

        return tempdir

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
            file=raw_info.split(",")[0],
            line=-1,
            function_name=raw_info.split(",")[2],
        )

    def _parse_callee_raw_info(self, raw_info: str) -> Callee:
        return Callee(
            file=raw_info.split(",")[0],
            line=int(raw_info.split(",")[1], 10),
            function_name=raw_info.split(",")[2],
        )

    def _parse_callstate_raw_info(self, raw_info: str, callee: Callee) -> CallState:
        return CallState(
            file=raw_info.split(",")[0],
            line=int(raw_info.split(",")[1], 10),
            callee=callee,
        )

    def _calc_global_callstack(
        self, caller: FunctionInfo, callee: FunctionInfo, caller_called_lineno: int
    ) -> None:
        if len(self._global_callstack) == 0:
            self._global_callstack.append([callee, -1])
            return

        for stack_idx, function in reversed(list(enumerate(self._global_callstack))):
            if (
                function[0].function_name == caller.function_name
                and function[0].file == caller.file
            ):
                if function[1] == -1:
                    latest_caller_index = stack_idx
                    self._global_callstack[stack_idx][1] = caller_called_lineno
                    break
                elif function[1] == caller_called_lineno:
                    latest_caller_index = stack_idx
                    break
                else:
                    continue

        else:
            # TODO: Is this strategy is robust? (don't have false positive?)
            self._global_callstack.append([callee, -1])
            return

        self._global_callstack = self._global_callstack[: latest_caller_index + 1]
        self._global_callstack.append([callee, -1])

    def _get_caller_from_global_callstack(self) -> Caller | None:
        if len(self._global_callstack) < 2:
            return None
        return self._global_callstack[-2][0]

    def parse_raw_trace_data_for_edges(self) -> Relations:
        trace_data = self._trim_trace_data(self.raw_trace_data)

        # NOTE: Raw trace data is like:
        # caller-filename:caller-lineno:caller-function-name
        # |-->|
        # callee-filename:callee-lineno:callee-function-name
        caller_map = {}  # Dictionary to map caller to relation index

        relations = Relations()

        for line in trace_data:
            thread_id_str, callstate_raw_info, callee_raw_info = line.split("|-->|")
            caller = self._parse_caller_raw_info(callstate_raw_info)
            callee = self._parse_callee_raw_info(callee_raw_info)
            callstate = self._parse_callstate_raw_info(callstate_raw_info, callee)

            if caller in caller_map:
                relation_idx = caller_map[caller]
                relation = relations[relation_idx]

                if not callstate in relation.callees:
                    relation.callees.append(callstate)

            else:
                relations.append(Relation(caller=caller, callees=[callstate]))

        return relations

    def parse_raw_data_for_trace(self) -> dict[int, Relations]:
        calltraces: dict[int, Relations] = defaultdict(Relations)

        for line in self.raw_trace_data:
            thread_id_str, callstate_raw_info, callee_raw_info = line.split("|-->|")
            thread_id = int(thread_id_str, 10)
            caller = self._parse_caller_raw_info(callstate_raw_info)
            callee = self._parse_callee_raw_info(callee_raw_info)
            callstate = self._parse_callstate_raw_info(callstate_raw_info, callee)

            # TODO: Can we parse untracked function information?
            calltraces[thread_id].append(Relation(caller=caller, callees=[callstate]))

        return calltraces

    def trace(self, harness: str, input_data: bytes) -> None:
        harness_path = os.path.join(self.workdir, harness)

        with TemporaryDirectory() as temp_dir:
            temp_input_path = os.path.join(temp_dir, "input")
            temp_trace_output_path = os.path.join(temp_dir, "trace.out")

            with open(temp_input_path, "wb") as f:
                f.write(input_data)

            cmd = [
                self.dynamorio_engine_path,
                "-disable_traces",
                "-c",
                self.dynamorio_plugin_path,
                temp_trace_output_path,
                "--",
                harness_path,
                "-runs=1",
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

    def cleanup(self) -> None:
        shutil.rmtree(self.workdir)
