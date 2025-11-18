#from jazzer_llm import oss-fuzz_corpus_observer, c_stuck_reason
#from .corpus_observer import *
from pathlib import Path
import logging
import time
import os
import configparser
#from pwn import *
import re
import sys
import litellm
from litellm import completion
from stuck_reason import * #lldb_run_program_execution_tracer
import openai
import os
import random

LITELLM_KEY = os.getenv("LITELLM_KEY")
AIXCC_LITELLM_HOSTNAME=os.environ.get("AIXCC_LITELLM_HOSTNAME")

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

# 1. Make the observer.
# 2. Check if coverage is stuck.
#   a. If not, sleep.
# 3. If coverage is stuck, select a random corpus item.
# 4. Run with coverage tracer to get where we are stuck and variable states.
# 5. Feed to LLM and generate new corpus.
# 6. Send back to fuzzer through corpus folder.
def invoke_llm_mutator(harness_id, target_program, selected_corpus, source_dir, fuzzing_harness):
    try:
        call_stack, executed_code, func_defs, variable_value = lldb_run_program_execution_tracer(
            program=target_program,
            corpus=selected_corpus,
            source_directory=source_dir,
            harness_file=fuzzing_harness
        )

        lines = call_stack.splitlines()
        truncate_index = -1
        if truncate_index != -1:
            call_stack = "\n".join(lines[:truncate_index + 1])
        
        start, end, harness_code = get_source_function_range(fuzzing_harness, "LLVMFuzzerTestOneInput")
        i = 0
        current_func_defs = harness_code

        for line in reversed(call_stack.split("\n")):
            if len(line) == 0:
                continue

            func_name = line.split("\t")[0]
            file_name = line.split("\t")[1]
            line_num = line.split("\t")[2]
            key_str = func_name+"\t"+file_name+"\t"+line_num+"\n"
            if file_name == "unknown" and ("LLVMFUzzerTestOneInput" not in func_name):
                continue
            key_str = func_name+"\t"+file_name+"\t"+line_num+"\n"
            if ("std::" in func_name or "__gnu" in func_name):
                continue
            start_line, end_line, code = get_function_def(file_name, func_name, source_dir, int(line_num))
            if key_str in executed_code:
                uncovered_lines = []
                if("LLVMFuzzerTestOneInput" in func_name):
                    uncovered_lines = get_uncovered_lines(harness_code, executed_code[key_str])
                else:
                    uncovered_lines = get_uncovered_lines(code, executed_code[key_str])
                    current_func_defs += code
                
                if uncovered_lines:
                    corpus_bytes = Path(selected_corpus).read_bytes()
                    prompt = get_prompt_for_bytes(corpus_bytes, call_stack, fuzzing_harness, 
                                                current_func_defs, variable_value, uncovered_lines, func_name)

                    mutated_code = prompt_llm(prompt)
                    if isinstance(mutated_code, bytes):
                        seed = FuzzerSeeds(
                            harness_id = harness_id, 
                            origin = "c_llm",
                            data = [mutated_code],
                        )
                        producer = Producer(KAFKA_SERVER_ADDR, FUZZER_SEED_SUGGESTIONS_TOPIC)
                        producer.send_message(seed)
    except Exception as e:
        logger.info(f"Exception: {e} (Line: {e.__traceback__.tb_lineno})")

def get_uncovered_lines(code, executed):
    uncovered_code = []
    clean_executed_code = []
    for codeline in executed.split("\n"):
        dash_index = codeline.find("-")
        if dash_index != -1:
            clean_executed_code.append(codeline[dash_index + 1:].strip())
    for codeline in code.split("\n"):
        if codeline.strip() not in clean_executed_code:
            uncovered_code.append(codeline)
    return uncovered_code

def get_prompt_for_bytes(corpus: bytes, trace: str, 
        harness : str, func_defs : str, variable_value: str, 
        uncovered_code, function_name) -> str:
    harness = Path(harness)
    frame_chunk = ""
    prompts = []
    if not harness.exists():
        logging.warning("Source directory %s does not exist", harness)
    with open(harness, 'rb') as f:  # Open in binary mode to handle all types of data
        harness_chunk = f.read().strip()

    frame_chunk = trace
    # Limit the corpus sample to only 256 bytes.
    corpus_hexstring = ''.join(f'{byte:02x}' for byte in corpus) 
    corpus_sample = corpus[:256].hex()
    if len(corpus) > 256:
        corpus_sample += "..."
    prompt = f"""\
We are trying to explore all the code paths in a C program using fuzzing. 
The entrypoint of the program is the LLVMInputTest in the following code:

{harness_chunk}

The byte array parameter passed in was 0x{corpus_sample}, the corresponding
hex string is {corpus_hexstring}
During execution, the program reached the following frame:

{frame_chunk}

The function definitions are as follows:

{func_defs}

The variable values before each frame exit are:

{variable_value}

Now based on the covered code and uncovered code, please mutate the input bytes and reach
the uncovered code. 

uncovered code in function {function_name}:

{"\n".join(uncovered_code)}

Your task is to generate a high quality new input that will help explore uncovered code paths in the function. The input should be generated directly as a sequence of bytes, based on the following considerations:

The structure of the input (e.g., offsets, lengths, or subfield of the structure type that the bytes will be translated to, or specific bytes that might influence control flow).
The uncovered code paths and the conditions required to reach them.
Any patterns or constraints in the input that are relevant to the program's logic and input format.
Respond with only the generated byte array splited by space. Do not include any additional text, explanations, or comments. Do not include any additional text, explanations, or comments.
"""
    return prompt

def get_source_function_range(src_filename, function_name):
    if "LLVMFuzzerTestOneInput" in function_name:
        function_name = "LLVMFuzzerTestOneInput"
    with open(src_filename, 'r') as file:
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
                            if function_name in sub_child.text.decode():
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
def get_function_def(src_filename, function_name, source_directory: Path, line_num):
    # Parse the source code
    if "/" in str(src_filename):
        src_filename = str(src_filename).split("/")[-1]
    abs_path = source_directory / src_filename

    if isLibfile(src_filename):
        return 0, 0, ""
    filepath = ""
    if filepath == "":
        for file_path in Path(source_directory).rglob(src_filename):
            if file_path.is_file():
                filepath = file_path.resolve()
    if filepath == "":
        return 0, 0, ""
    with open(file_path, 'r') as file:
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
                            startline = node.start_point[0] + 1
                            endline = node.end_point[0] + 1
                            if line_num <= endline and line_num>=startline:
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

os.environ["OPENAI_API_KEY"] = LITELLM_KEY
os.environ["ANTHROPIC_API_KEY"] = LITELLM_KEY

models = [
    "gpt-4.1",
    "o3",
    "o4-mini",
    "claude-sonnet-4-20250514",
]

model_name = random.choice(models)

# Fallback to asking user to get LLM responses if LITELLM_KEY is not present.
if 'LITELLM_KEY' in os.environ:
    def prompt_llm(prompt):
        try:
            messages = [{"role": "user", "content": prompt}]
            response = completion(
                model=model_name,
                messages=messages,
                api_base = AIXCC_LITELLM_HOSTNAME,
            )
            code = response.choices[0].message.content
            return code
        except (openai.RateLimitError,
                openai.APITimeoutError,
                openai.InternalServerError,
                openai.UnprocessableEntityError) as e:
            logger.error("OpenAI rate limit or similar, sleeping and retrying")
            sleep_time = 2*60 #set as 2min for now
            time.sleep(sleep_time)
        except (openai.APIConnectionError,
                    openai.NotFoundError,
                    openai.BadRequestError,
                    openai.AuthenticationError,
                    openai.ConflictError,
                    openai.PermissionDeniedError) as e:
                logger.error("OpenAI other error: %s", e)

else:
    def prompt_llm(prompt):
        global total_cost, total_tokens
        messages = [{ "content": prompt,"role": "user"}]
        try:
            response = completion(
                model = model_name, 
                messages=messages,
                temperature = 0.1
            )

            answer = response['choices'][0]['message']['content']
            code = answer.strip()
            return code
        except (openai.RateLimitError,
                openai.APITimeoutError,
                openai.InternalServerError,
                openai.UnprocessableEntityError) as e:
            logger.error("OpenAI rate limit or similar, sleeping and retrying")
            sleep_time = 2*60 #set as 2min for now
            time.sleep(sleep_time)
        except (openai.APIConnectionError,
                    openai.NotFoundError,
                    openai.BadRequestError,
                    openai.AuthenticationError,
                    openai.ConflictError,
                    openai.PermissionDeniedError) as e:
                logger.error("OpenAI other error: %s", e)

