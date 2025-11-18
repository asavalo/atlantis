# Module for getting the reasons why execution is stuck.
from typing import List, Optional
from pathlib import Path
from dataclasses import dataclass
import logging
import subprocess
import re
#from pwn import process, gdb
import time
import os

logging.basicConfig(
    filename = "output.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("c_llm_mutator")

import tree_sitter_cpp
from tree_sitter import Language, Parser, Tree, Node

CPP_LANGUAGE = Language(tree_sitter_cpp.language())
cpp_parser = Parser(CPP_LANGUAGE)

function_call_counts = {}

import lldb
@dataclass
class ExecutionFrame:
    file: str
    function_name: str
    start_line: Optional[int]
    end_line: Optional[int]

@dataclass
class StuckExecutionTrace:
    frames: List[ExecutionFrame]

def find_longest_backtrace_block(output):
    blocks = output.strip().split("\n\n")
    
    longest_block = None
    max_backtrace_length = 0
    
    for block in blocks:
        backtrace_lines = [line for line in block.splitlines() if line.strip().startswith("#")]
        
        if len(backtrace_lines) > max_backtrace_length:
            max_backtrace_length = len(backtrace_lines)
            longest_block = block
    
    return longest_block
def isLibfile(filename):
    if filename.startswith("std"):
        return True
    if filename == "unknown":
        return True
    return False
def lldb_parse_execution_trace(output: str, source_directory: Path) -> StuckExecutionTrace:
    frames = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        
        function_name = line.split("\t")[0].strip()
        src_filename = line.split()[1].strip()
        line_info = get_function_range(filepath, function_name, source_directory)
        if line_info:
            startline, endline = line_info.start_line, line_info.end_line
            frames.append(
                ExecutionFrame(
                    file=filepath, function_name=function_name, start_line=startline, end_line=endline
                )
            )
    return StuckExecutionTrace(frames=frames) 

def parse_execution_trace(output: str) -> StuckExecutionTrace:
    frames = []
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        if not line.startswith("#"):
            continue
        line = line.lstrip('#0123456789').lstrip()

        pattern = r'^(?:0x[0-9a-fA-F]+\s+in\s+)?(.*?)\s+\(.*?\)\s+at\s+(.*?):(\d+)$'
        match = re.match(pattern, line.strip())

        if match:
            function_name = match.group(1).strip()
            filename = match.group(2).strip()
            if not os.path.exists(filename):
                continue
            line_info = get_function_range(filename, function_name)
            if line_info:
                startline, endline = line_info.startline, line_info.endline
                frames.append(
                    ExecutionFrame(
                        file=filename, function_name=function_name, start_line=startline, end_line=endline
                    )
                )

    return StuckExecutionTrace(frames=frames)

def extract_function_names(source_code):
    # Parse the source code
    tree = cpp_parser.parse(bytes(source_code, "utf8"))
    function_names = []

    def traverse(node):
        if node.type == "function_definition":
            for child in node.children:
                if child.type == "function_declarator":
                    for sub_child in child.children:
                        if sub_child.type == "identifier":
                            if not (sub_child.text.decode().startswith("__")):
                                function_names.append(sub_child.text.decode())
        for child in node.children:
            traverse(child)

    traverse(tree.root_node)
    return function_names

def parse_functions_in_file(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            source_code = file.read()
        return extract_function_names(source_code)
    else:
        return []
def get_all_function(source_directory: Path):
    function_names = []
    for root, _, files in os.walk(source_directory):
        for file in files:
            if file.endswith((".c", ".h")):
                input_file = os.path.join(root, file)
                output_file = input_file+".i"
                compile_succeed = False
                try:
                    subprocess.run(
                        ["gcc", "-E", input_file, "-o", output_file],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    compile_succeed = True
                    function_names.extend(parse_functions_in_file(output_file))
                except subprocess.CalledProcessError as e:
                    pass
                if compile_succeed == False:
                    function_names.extend(parse_functions_in_file(input_file))
    return function_names

import subprocess
from pathlib import Path

def get_source_code_info(frame, src_dir):
    line_entry = frame.GetLineEntry()
    if not line_entry.IsValid():
        return None, None, None

    file_spec = line_entry.GetFileSpec()
    file_name = file_spec.GetFilename()
    line_num = line_entry.GetLine()
    
    filepath = ""
    for file_path in Path(src_dir).rglob(file_name):
        if file_path.is_file():
            filepath = file_path.resolve()
    if filepath == "":
        return file_name, line_num, None
    if line_num > 0:
        try:
            with open(filepath, "r") as f:
                lines = f.readlines()
                if line_num <= len(lines):
                    source_line = lines[line_num - 1].strip()  # 行号从 1 开始
                    return file_name, line_num, source_line
        except Exception as e:
            logger.info(f"Failed to read source file: {e}")

    return file_name, line_num, None

def capture_variable_values(frame):
    if not frame.IsValid():
        logger.error("Invalide frame provided.")
    """
    Capture the values of all local variables in the given frame.
    """
    var_values = {}
    for var in frame.GetVariables(True, True, False, True):
        var_name = var.GetName()
        var_value = var.GetValue()

    return var_values
def step_through_function(process, frame, src_dir):
    executed_code = ""
    call_stack = ""
    variable_values = []
    thread = frame.GetThread()
    func = frame.GetFunction()
    if not func.IsValid():
        #logger.info("Invalid function in frame #0.")
        return executed_code, variable_values
    if (func.GetName() == "LLVMFuzzerTestOneInput"):
        return executed_code, variable_values
    # get function return address
    return_address = func.GetEndAddress().GetLoadAddress(process.GetTarget())
    if not return_address:
        logger.info("Failed to get function return address.")
        return executed_code, variable_values

    # step till function finished
    while True:
        file_name, line_num, source_line = get_source_code_info(frame, src_dir)
        if file_name and line_num:
            log_entry = f"{file_name}:{line_num} - {source_line}\n"
            executed_code += log_entry
        var_values = capture_variable_values(frame)
        if var_values:
            variable_values.append(var_values)
        thread.StepOver()

        current_pc = frame.GetPC()
        if current_pc >= return_address:
            break

        frame = thread.GetFrameAtIndex(0)
    return executed_code, variable_values

def lldb_run_program_execution_tracer(program: str, corpus: str, source_directory: Path, harness_file: Path):
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)
    error = lldb.SBError()

    target = debugger.CreateTarget(
        str(program),    # exe_path
        None,            # target_triple\
        None,            # platform_name
        False,           # add_dependent_modules
        error            # SBError 
    )
    
    for module in target.module_iter():
        for symbol in module:
            if symbol.GetType() == lldb.eSymbolTypeCode:
                fname = symbol.GetName()
                if not (fname.startswith(('.', '_')) or '..' in fname):
                    bp = target.BreakpointCreateByName(fname)

    deepest_trace = ""
    func_list = get_all_function(source_directory)

    func_defs = ""
    for func_name in func_list:
        breakpoint = target.BreakpointCreateByName(func_name)
        func = target.FindFunctions(func_name).GetContextAtIndex(0).GetFunction()
        if func.IsValid():
            return_address = func.GetEndAddress()
            return_breakpoint = target.BreakpointCreateByAddress(return_address.GetLoadAddress(target))

        
    launch_info = lldb.SBLaunchInfo([str(corpus)])
    error = lldb.SBError()
    process = target.Launch(launch_info, error)

    last_frame = ""
    stuck_backtrace_str = ""
    backtrace_str = ""
    max_trace_len = 0
    trace_len = 0
    code_executed = {}
    max_code_executed = {}

    current_func_defs = ""
    update = False
    
    max_variable_vals = {}
    values = {}
    
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[mK]")
    if process and process.IsValid():
        logger.info(f"Process launched successfully!")
        while process.GetState() == lldb.eStateStopped:
            thread = process.GetThreadAtIndex(0)
            if (update == True and trace_len>=max_trace_len):
                stuck_backtrace_str = backtrace_str
                max_trace_len = trace_len
                func_defs = current_func_defs
                max_variable_vals = values

            update = False
            backtrace_str = ""
            current_func_defs = ""
            trace_len = 0
            values = {}
            code_executed = {}
            if thread.IsValid():
                #Skip and return the frame to avoid infinite loop
                for frame in thread.frames:
                    func_name = frame.GetFunctionName() or "unknown"
                    file_spec = frame.GetLineEntry().GetFileSpec() if frame.GetLineEntry() else None
                    file_name = file_spec.GetFilename() if file_spec else "unknown"
                    
                    if func_name == "unknown" or file_name == "unknown" or any(s in file_name for s in ["lsan", "asan", "sanitizer"]):
                        continue
                    if func_name not in function_call_counts:
                        function_call_counts[func_name] = 0
                    function_call_counts[func_name] += 1
                    if function_call_counts[func_name] > 3:
                        func = frame.GetFunction()
                        return_value = None
                        if func.IsValid():
                            return_type = func.GetType().GetFunctionReturnType()
                            if return_type.IsPointerType():
                                return_value = frame.EvaluateExpression("(void*)0")
                            elif return_type.GetName() in ["int", "bool", "long"]:
                                return_value = frame.EvaluateExpression("0")
                            else:
                                logger.warning(f"Unhandled return type: {return_type.GetName()}, skipping")
                                continue
                        else:
                            return_value = frame.EvaluateExpression("(void*)0")
                
                        logger.info(f" Forcing {func_name} to return after 3+ calls")
                        frame.thread.ReturnFromFrame(frame, return_value)
                        continue

                first_check = True
                for frame in thread.frames:
                    last_trace, values = step_through_function(process, frame, source_directory)
                    break
                for frame in thread.frames:                   
                    func_name = frame.GetFunctionName() or "unknown"
                    file_spec = frame.GetLineEntry().GetFileSpec()
                    file_name = file_spec.GetFilename() or "unknown"
                    line_num = frame.GetLineEntry().GetLine() or "unknown"
                    frame_str = f"{func_name}\t{file_name}\t{line_num}\n"

                    if func_name == "unknown" and file_name== "unknown" and line_num == "unknown":
                        continue
                    if ("lsan" not in file_name) and ("asan" not in file_name) and ("sanitizer" not in file_name):
                        trace_len += 1
                    if func_name != "unknown":
                        start, end, func_def = get_function_range(file_name, func_name, source_directory, harness_file)
                        current_func_defs += func_def
                    backtrace_str += frame_str
                    executed_code, values = step_through_function(process, frame, source_directory)
                    if executed_code:
                        code_executed[frame_str] = executed_code
                    update = True
                if (trace_len > max_trace_len):
                    stuck_backtrace_str = backtrace_str
                    max_trace_len = trace_len
                    #deepest_trace = last_trace
                    max_variable_vals = values
                    func_defs = current_func_defs
                    max_code_executed = code_executed
            process.Continue()
    else:
        logger.info("Failed to launch process.")
    lldb.SBDebugger.Destroy(debugger)
    return stuck_backtrace_str, max_code_executed, func_defs, max_variable_vals

def get_endline(file_name, function_name, start_line):
    with open(file_name, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    brace_count = 0
    inside_function = False

    for i, line in enumerate(lines[start_line - 1:], start=start_line): 
        stripped = line.strip()

        if not inside_function and (re.match(rf'\b{function_name}\b\s*\(', stripped) or i == start_line):
            inside_function = True
        
        if inside_function:
            brace_count += stripped.count('{')
            brace_count -= stripped.count('}')
            if brace_count == 0 and inside_function:
                return i 
    return 

def get_function_range(src_filename, function_name, source_directory, harness_file):
    # Parse the source code
    if "/" in src_filename:
        src_filename = src_filename.split("/")[-1]
    i_file = (src_filename+".i")
    abs_path = source_directory/src_filename
    if isLibfile(src_filename):
        return 0, 0, ""
    filepath = ""
    for file_path in Path(source_directory).rglob(i_file):
        if file_path.is_file():
            filepath = file_path.resolve()
    if filepath == "":
        for file_path in source_directory.rglob(src_filename):
            if file_path.is_file():
                filepath = file_path.resolve()
    if filepath == "":
        filepath = harness_file
    if filepath == "" or not os.path.exists(filepath):
        return 0, 0, ""
    with open(filepath, 'r') as file:
        source_code = file.read()
    tree = cpp_parser.parse(bytes(source_code, "utf8"))
    startline = 0
    endline = 0
    function_source = ""
    def traverse(node):
        if node.type == "function_definition":
            for child in node.children:
                if child.type == "function_declarator":
                    for sub_child in child.children:
                        if sub_child.type == "identifier":
                            if sub_child.text.decode() == function_name:
                                startline = node.start_point[0] + 1
                                endline = node.end_point[0] + 1
                                function_source = "\n".join(source_code.splitlines()[startline - 1:endline])
                                return startline, endline, function_source
        for child in node.children:
            result = traverse(child)
            if result:
                return result
        return None
    result = traverse(tree.root_node)
    if result:
        return result
    else:
        return 0,0,""

