import logging
import os
import re
from typing import List, Set, Any
from enum import Enum
from pathlib import Path
import glob
import asyncio
import json
import time
from dataclasses import dataclass

from libatlantis.protobuf import (
    SarifHarnessReachability,
    SarifDirected,
    DeltaDirected,
    CPConfig,
    LibSarifHarnessReachability,
    StringList,
    protobuf_repr,
)
from libatlantis.constants import (
    KAFKA_SERVER_ADDR,
    SARIF_HARNESS_REACHABILITY_TOPIC,
    SARIF_DIRECTED_TOPIC,
    DELTA_DIRECTED_TOPIC,
)
from libmsa.kafka.producer import Producer
from libSarif import (
    CallGraph,
    get_subgraph,
    get_rechable_function_with_line, # keep barbequeue'ing
    get_shortest_path,
)
from libSarif.models import Function

from .diff_analysis.parse import get_prioritized_delta_locations

import tree_sitter_cpp
from tree_sitter import Language, Parser, Tree, Node
CPP_LANGUAGE = Language(tree_sitter_cpp.language())
cpp_parser = Parser(CPP_LANGUAGE)


REACHABILITY_SHARE_DIR = os.environ.get("REACHABILITY_SHARE_DIR")
LITELLM_KEY = os.getenv("LITELLM_KEY")
AIXCC_LITELLM_HOSTNAME=os.environ.get("AIXCC_LITELLM_HOSTNAME")

logger = logging.getLogger("harness_reachability")

suffix_blacklist = ['.yaml', '.json', '.bazel', '.txt']

class HarnessReachability(Enum):
    UNREACHABLE = 0
    WEAK_REACHABLE = 1
    STRONG_REACHABLE = 2

@dataclass
class HandlerContext:
    tracked_time: float
    # NOTE can add more stuff, e.g. start_time

def dict_to_reachability_msg(python_dict: dict[str, list[str]]) -> LibSarifHarnessReachability:
    """Convert Python dict[str, list[str]] to protobuf message."""
    dict_todo = {}
    for location, harnesses in python_dict.items():
        # Create a StringList message for each list of strings
        string_list = StringList()
        string_list.values.extend(harnesses)  # Add all strings to the repeated field
        # Add to the map
        dict_todo[location] = string_list

    proto_msg = LibSarifHarnessReachability(
        location_harnesses_disabled = dict_todo
    )
    return proto_msg
    
class HarnessReachabilityContext:
    def __init__(self):
        self.files_state = {} # dir -> file_path -> file mtime
        self.reachable_functions = {} # harness_id -> reachable func_names
        self.sarif_reports = {} # sarif_id -> reachable harness_id
        self.done_sarifs = set()
        self.interval = 5 
        self.diff_functions = set()
        self.cp_name = None
        self.locations = []
        self.kafka_producer_reachability = Producer(KAFKA_SERVER_ADDR, SARIF_HARNESS_REACHABILITY_TOPIC)
        self.kafka_producer_directed = Producer(KAFKA_SERVER_ADDR, SARIF_DIRECTED_TOPIC)

        self.diff_line_numbers = {} # changed filename->line range
        self.harness_ids = []
        self.location_harness_reachability = {} # location -> harness_id -> reachability
        self.location_to_disable_harnesses = {} # location -> list of harness_ids
        self.snapshot_location_to_disable_harnesses = {}
        self.last_turn_on_harnesses = set()
    
    def register_cp(self, cp_config: CPConfig):
        if self.cp_name:
            return
        self.cp_name = cp_config.cp_name
        self.src_path = Path(cp_config.cp_src_path)
        self.oss_fuzz_path = Path(cp_config.oss_fuzz_path)
        self.mode = cp_config.mode
        self.diff_path = self.oss_fuzz_path / "projects" / self.cp_name / ".aixcc/ref.diff"
        
        if self.mode == "delta":
            # set the diff lines
            self.get_diff_lines()
            self.send_delta_location_message()
        else:
            logger.info(f"No diff file found for {self.cp_name}")

    async def scan_dir(self, dir_path: Path):
        """
        Remote NFS does not support fs events so we can only use dumb scanning
        """
        current_state = {}
        black_list = [".lafl_lock", ".tmp", ".metadata"]
        try:
            for file_path in dir_path.glob('*'): # no recursive searching!
                try:
                    if file_path.is_dir() or file_path.suffix in black_list:
                        continue
                    file_mtime = file_path.stat().st_mtime 
                    current_state[file_path] = file_mtime
                except FileNotFoundError:
                    continue
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
        return current_state

    async def scan_dir_1_level(self, dir_path: Path):
        current_state = {}
        black_list = [".lafl_lock", ".tmp", ".metadata"]
        try:
            for entry in dir_path.iterdir():
                if not entry.is_dir():
                    continue
                try:
                    for file_path in entry.iterdir():  # only 1 level deep
                        try:
                            if file_path.is_dir() or file_path.suffix in black_list:
                                continue
                            file_mtime = file_path.stat().st_mtime
                            current_state[file_path] = file_mtime
                        except FileNotFoundError:
                            continue
                except Exception as inner_e:
                    logger.warning(f"Error scanning subdir {entry}: {inner_e}")
        except Exception as e:
            logger.error(f"Error scanning directory: {e}")
        return current_state

    async def start_monitoring(self, dir_path: Path, file_handler, time_handler=None, scan_closure=None):
        if scan_closure is None:
            scan_closure = self.scan_dir

        context = HandlerContext(
            tracked_time = time.time()
        )
        self.files_state[dir_path] = {}
        while True:
            current_state = await scan_closure(dir_path)
            added_files = [f for f in current_state if f not in self.files_state[dir_path]]
            modified_files = [
                f
                for f in current_state
                if f in self.files_state[dir_path] and current_state[f] != self.files_state[dir_path][f]
            ]

            for file in added_files + modified_files:
                await file_handler(file, context)

            # update state
            self.files_state[dir_path] = current_state

            # call custom handler if available
            if time_handler:
                await time_handler(context)

            await asyncio.sleep(self.interval)
            logger.info(f"** heartbeat ** -> monitoring {dir_path}")
        
    async def reachability_handler(self, file_path: Path, context: HandlerContext):
        try:
            file_text =  file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Could not read file {file_path}: {e}")
            return
        
        harness_name_pattern = r'^(?P<harness_name>.+)-(?P<checksum>[^_]+)\.json$'
        match = re.match(harness_name_pattern, file_path.name)
        if match:
            harness_name = match.group("harness_name")
            if harness_name == "whole":
                logger.info("Ignoring whole call graph dump...")
                return
            logger.info(f"New reachability report for harness {harness_name}")
            try:
                self.libsarif_reachable(harness_name, file_path)
            except:
                dir_path = file_path.parent
                logger.warning(f"File at {file_path} couldn't be parsed")
                if dir_path in self.files_state and file_path in self.files_state[dir_path]:
                    logger.warning("Popping from state")
                    self.files_state[dir_path].pop(file_path)
                return
        else:
            logger.error("File name does not match the pattern harness-md5.json")
            return
        
        # using regex to be fast
        self.harness_ids.append(harness_name)

    # sarif reports format is not fixed, normalize here
    # WARN: This is just from reading the json files! We need to make sure that the format is fixed!
    # i.e. is reachability_results a list? can we expect multiple code locations?
    def get_sarif_info(self, sarif_json):
        sarif_results = {"reachable": False}
        if sarif_json.get("analysis_result"):
            sarif_json = sarif_json.get("analysis_result")
            harness = sarif_json.get("reachable_harness")
            if harness:
                sarif_results["reachable"] = True
                sarif_results["reachable_harnesses"] = [harness]
                sarif_results["code_location"] = sarif_json["reachability_results"][0]["code_location"]
        else:
            sarif_results = sarif_json
        return sarif_results

    def send_delta_location_message(self):
        try:
            # NOTE this is for debugging, might as well keep
            # locations = ["HTMLparser.c:3700", "HTMLparser.c:3330", "HTMLparser.c:4720"]
            locations = get_prioritized_delta_locations(self.diff_path)
            logger.info(f"Chosen diff locations: {locations}")
            if locations:
                producer = Producer(KAFKA_SERVER_ADDR, DELTA_DIRECTED_TOPIC)
                msg = DeltaDirected(locations=locations)
                producer.send_message(msg)
            self.locations = locations
        except:
            pass

    async def sarif_handler(self, file_path: Path, context: HandlerContext):
        filename = file_path.name
        report_pattern = r'^[0-9a-f\-]+\.json$'
        if not re.match(report_pattern, filename):
            logger.info(f"File name does not match the pattern sarif_id.json {filename}")
            return
        
        sarif_id = file_path.stem
        fuzzer = file_path.parent.name
        
        if sarif_id in self.done_sarifs:
            logger.info(f"Skipping {sarif_id} because we already know it is done" )
            return

        if file_path.suffix.lower() == "done":
            logger.info(f"SARIF {sarif_id} seems to be done")
            self.done_sarifs.add(sarif_id)
            return
            
        try:
            file_text =  file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Could not read file {file_path}: {e}")
            return
        
        try:
            sarif_analysis_result = json.loads(file_text)
        except Exception as e:
            logger.error(f"Could not parse SARIF file {file_path}: {e}")
            # scan_1_dir_level, so go 2 levels up
            dir_path = file_path.parent.parent
            if dir_path in self.files_state and file_path in self.files_state[dir_path]:
                logger.warning("Popping from state")
                self.files_state[dir_path].pop(file_path)
            return

        if sarif_id != sarif_analysis_result.get("sarif_id"):
            logger.error("SARIF ID mismatch!")
            return

        normalized_sarif_info = self.get_sarif_info(sarif_analysis_result)
        is_reachable = normalized_sarif_info.get("reachable")
        if is_reachable:
            harnesses = normalized_sarif_info.get("reachable_harnesses")
            location = normalized_sarif_info.get("code_location")
            path = location["file"]["name"]
            line = location["start_line"]
            msg_loc = f"{Path(path).name}:{line}"
            self.sarif_reports[sarif_id] = harnesses
            msg = SarifDirected(
                location = msg_loc,
                harness_id = fuzzer,
                sarif_id = sarif_id,
            )
            self.kafka_producer_directed.send_message(msg)

    async def send_reachability_results(self, context: HandlerContext):
        now = time.time()
        logger.debug(f"** heartbeat ** -> handler at {now}")
        if now - context.tracked_time < 5 * 60:
            return
        # update tracked time
        context.tracked_time = now
        
        turn_on_harnesses = self.get_harness_ids()
        turn_off_harnesses = set([x for x in self.harness_ids if x not in turn_on_harnesses])

        if turn_on_harnesses == self.last_turn_on_harnesses:
            logger.info("Same turn_on_harnesses results as the last round.")
            return
        
        self.last_turn_on_harnesses = turn_on_harnesses
        logger.info(f"turn_off_harnesses : {turn_off_harnesses}")
        if len(turn_off_harnesses) > 0:
            msg = SarifHarnessReachability(
                harness_ids = turn_off_harnesses
            )
            self.kafka_producer_reachability.send_message(msg)
        else:
            logger.info("No harnesses to turn off, from the results of reachability results")
        self.reachable_functions = {}

    async def send_libsarif_reachability_results(self, context: HandlerContext):
        now = time.time()
        logger.debug(f"** heartbeat ** -> handler at {now}")
        if now - context.tracked_time < 5 * 60:
            return
        # update tracked time
        context.tracked_time = now

        for location, harness_map in self.location_harness_reachability.items():
            harnesses_to_disable = []
            # first see if everything is there exists a harness that's strongly reachable.
            if any(reachability == HarnessReachability.STRONG_REACHABLE for reachability in harness_map.values()):
                # find harnesses that are not strongly reachable
                for harness_id, reachability in harness_map.items():
                    if reachability != HarnessReachability.STRONG_REACHABLE:
                        logger.info(f"Weakly reachable or unreachable harness {harness_id} at {location} in a strongly reachable world")
                        harnesses_to_disable.append(harness_id)
                if not harnesses_to_disable:
                    logger.info(f"Everything is strongly reachable at {location}")
            # elif there exists a harness that's weakly reachable
            elif any(reachability == HarnessReachability.WEAK_REACHABLE for reachability in harness_map.values()):
                # find harnesses that are not weakly reachable
                for harness_id, reachability in harness_map.items():
                    if reachability != HarnessReachability.WEAK_REACHABLE:
                        logger.info(f"Unreachable harness {harness_id} at {location} in a weakly reachable world")
                        harnesses_to_disable.append(harness_id)
                if not harnesses_to_disable:
                    logger.info(f"Everything is weakly reachable at {location}")
            else:
                logger.info(f"Wow, everything is unreachable at {location}")
            self.location_to_disable_harnesses[location] = harnesses_to_disable

        if self.snapshot_location_to_disable_harnesses != self.location_to_disable_harnesses:
            self.snapshot_location_to_disable_harnesses = self.location_to_disable_harnesses
            msg = dict_to_reachability_msg(self.location_to_disable_harnesses)
            logger.info(f'Sending message: {protobuf_repr(msg)}')
            self.kafka_producer_reachability.send_message(msg)

    async def seed_handler(self, file_path: Path):
        pass

    def get_diff_lines(self):
        logger.info("Inside get_diff_lines")
        if not os.path.exists(self.diff_path):
            logger.info(f"No diff file found at {self.diff_path}, skipping.")
            self.diff_line_numbers = {}
            return
        with open(self.diff_path, 'r', encoding='utf-8') as file:
            diff_text = file.read()
        diff_lines = {}
        file_pattern = re.compile(r'^diff --git a/(.*?) b/(.*?)$')
        hunk_pattern = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
        filename = ""
        for line in diff_text.split("\n"):
            file_match = file_pattern.match(line)
            if file_match:
                filename = file_match.group(1)
                if filename not in diff_lines and (not filename.endswith(tuple(suffix_blacklist))):
                    diff_lines[filename] = []
                continue
            hunk_match = hunk_pattern.match(line)
            if hunk_match:
                #Use the heuristics that there are 3 lines context before and after
                #For example, +3302, 334 ends up with [3305,3632]
                old_start, old_lines, new_start, new_lines = hunk_match.groups()
                
                if not filename.endswith(tuple(suffix_blacklist)):
                    diff_lines[filename].append((
                        int(new_start)+3, 
                        max(int(new_start) + int(new_lines or 1) - 4, 1)
                    ))
                continue
        self.diff_line_numbers = diff_lines
        logger.info(f"diff_line_numbers : {self.diff_line_numbers}")

    # Match the harness_id purely based on the line number, returns set of harnesses that are reachable
    def get_harness_ids(self):
        harness_ids = set()
        if os.path.exists(REACHABILITY_SHARE_DIR):
            logger.info(f"REACHABILITY_SHARE_DIR = {REACHABILITY_SHARE_DIR}")
        else:
            logger.info("REACHABILITY_SHARE_DIR not finished.")
        for result_file in os.listdir(REACHABILITY_SHARE_DIR):
            logger.info(f"result_file = {result_file}")
            if result_file.endswith('.json'):
                file_path = os.path.join(REACHABILITY_SHARE_DIR, result_file)
                harness_id = result_file.split("-")[0]
                try:
                    if self.find_overlap(file_path):
                        harness_ids.add(harness_id)
                except Exception as e:
                    logger.info(f"{e}")
        logger.info(f"harness_ids = {harness_ids}")
        return harness_ids

    def libsarif_reachable(self, harness_id: str, file_path: Path):
        callgraph_path = str(file_path)
        callgraph = CallGraph().from_json(callgraph_path)
        for location in self.locations:
            if location not in self.location_harness_reachability:
                self.location_harness_reachability[location] = {}

            # split location into file_name and line_number
            file_name, line_number = location.split(":")
            rechable_function: Function | None = get_rechable_function_with_line(
                callgraph, file_name, int(line_number), include_uncertain=True
            )
            if rechable_function:
                subgraph = get_subgraph(callgraph, rechable_function)
                shortest_path = get_shortest_path(subgraph, rechable_function, include_uncertain=False)
                if shortest_path:
                    self.location_harness_reachability[location][harness_id] = HarnessReachability.STRONG_REACHABLE
                    logger.info(f"Strongly reachable harness {harness_id} at {location}")
                    continue
                shortest_path = get_shortest_path(subgraph, rechable_function, include_uncertain=True)
                if shortest_path:
                    self.location_harness_reachability[location][harness_id] = HarnessReachability.WEAK_REACHABLE
                    logger.info(f"Weakly reachable harness {harness_id} at {location}")
                    continue
                self.location_harness_reachability[location][harness_id] = HarnessReachability.UNREACHABLE
                logger.info(f"Unreachable harness {harness_id} at {location}")
            self.location_harness_reachability[location][harness_id] = HarnessReachability.UNREACHABLE
            logger.info(f"Unreachable function for location {location}")

    def find_overlap(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
                
            entrypoint = json_data.get("entrypoint")
            # This means the file_path is a whole call graph integrated from all the harness
            # Not a harness_id file, ususally named whole-*.json
            if isinstance(entrypoint, list):
                return False
            entrypoint = json_data.get("entrypoint", {}).get("data", {})
        
            if entrypoint:
                if (self.has_overlap(entrypoint)):
                    return True

            for node in json_data.get("graph", {}).get("nodes", []):
                func_info = node.get("data", {})
                if func_info:
                    if (self.has_overlap(func_info)):
                        return True
        except Exception as e:
            logger.info(f"Error at line {e.__traceback__.tb_lineno}: {e}")
        return False
    def has_overlap(self, data):
        diff_lines = self.diff_line_numbers
        try:
            func_name = data.get("func_name")
            start_line = data.get("start_line")
            end_line = data.get("end_line")
            file_name = data.get("file_name")
            if (start_line is not None) and (end_line is not None):
                start_line = int(start_line)
                end_line = int(end_line)
            
                for diff_file_name in diff_lines:
                    if file_name.endswith(diff_file_name):
                        for ranges in diff_lines[diff_file_name]:
                            start, end = ranges
                            start = int(start)
                            end = int(end)
                            if not (start_line > end or end_line < start):
                                return True
            else:
                logger.info(f"Traverse the file to match the function {func_name} in file {file_name}")
                for diff_file_name in diff_lines:
                    logger.info(f"diff_file_name : {diff_file_name}")
                    if file_name.endswith(diff_file_name):
                        logger.info(f"Matching the {func_name} in {file_name} in range of {diff_file_name}")
                        if self.match_func(func_name, diff_file_name):
                            return True
        except Exception as e:
            logger.info(f"Error at line {e.__traceback__.tb_lineno}: {e}")
        return False
    def match_func(self, func, diff_file_name):
        file_name = Path(self.src_path) / diff_file_name
        ranges = self.diff_line_numbers[diff_file_name]
        source_code = ""
        if os.path.exists(file_name):
            with open(file_name, 'r') as file:
                source_code = file.read()
        else:
            logger.info(f"{file_name} not found.")
            return False
        logger.info(f"Traverse the source code : {file_name}")
        tree = cpp_parser.parse(bytes(source_code, "utf8"))
        def traverse(node):
            if node.type == "function_definition":
                for child in node.children:
                    if child.type == "function_declarator":
                        for sub_child in child.children:
                            if sub_child.type == "identifier":
                                func_name = sub_child.text.decode()
                                start_line = node.start_point[0] + 1
                                end_line = node.end_point[0] + 1
                                for item in ranges:
                                    start, end = item
                                    start = int(start)
                                    end = int(end)
                                    if not (start_line > end or end_line < start):
                                        if func_name == func:
                                            logger.info(f"Find the func_name : {func_name}")
                                            return True
            for child in node.children:
                traverse(child)
        traverse(tree.root_node)
        return False


