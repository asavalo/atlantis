# Martian agent

Martian agent is an AI agent that fixes security bugs with pre-defined workflow.
The agent decomposes the patching process into two stages: Fault Localization and Patch Generation.
Each stage is handled by a ReAct-based agent, equipped with code searching tools and file editing tools.
Depending on the patch evaluation result, failed cases will receive feedback and the process will be retried.

<img src="./assets/martian_agent_architecture.png" alt="Martian Agent Architecture" width="600">

## QuickStart

```sh
$ uv sync
$ uv run scripts/setup.py
$ uv run benchmark -m apps.custom.martian_FL_o4_mini_CG_claude_4 scripts/benchmark/full/custom-c-mock-c-cpv-0-full.toml
```

## Core components

1. Fault Localizer (`packages/crete/framework/fault_localizer/services/coderover_k/__init__.py`)
    - Purpose: From given vulnerability (`Detection`) and the Crete environment (`Context`), analyze the vulnerability, find the buggy function and make a plan to fix it.
    - Implementation:
        - [LangChain's prebuilt **ReAct agent**](/packages/python_llm/agents/react.py)
        - 3 code searching tools: `search_symbol`, `search_string` and `view_file`
    - LLM model: OpenAI o4-mini
    - Output: Buggy function and a textual bug analysis report (including fix plan)

2. Patch Generator (`packages/crete/framework/coder/services/minimal/__init__.py`)
    - Purpose: Generate a patch in unified diff (udiff) format using the output from the fault localizer, including the identified buggy function and the textual bug description with the proposed fix plan.
    - Implementation:
        - [LangChain's prebuilt **ReAct agent**](/packages/python_llm/agents/react.py)
        - 3 file editing tools: `view_function`, `edit_function` and `add_import_module` (for only JAVA)
    - LLM model: Anthropic claude-4-sonnet
    - The user prompt is in [`MartianAgent._make_prompt` function](/packages/crete/framework/agent/services/martian/__init__.py#L248)

3. Feedback (`packages/crete/framework/agent/services/martian/__init__.py`)
    - Purpose: Depending on the patch evaluation result, it retries the process with appropriate feedback prompt.
    - Implementation: state machine

## Tools

### Code Searching Tools

#### 1. **search_symbol** (`packages/crete/framework/tools/services/search_symbol.py`)

- Tool name: `search_symbol`
- Parameters:
    - `symbol_name` (string, required): The name of the symbol to search
    - `file_or_directory_path` (string, optional): The target path to search the symbol. If it's not given, it'll search the whole codebase.
- Behavior:
    1. Uses `RipGrep` command line tool to find the **symbol use locations**.
    2. Uses "Go to Definition" feature of Language Server Protocol to find the **symbol def location**.
    3. Uses tree-sitter AST parser to get the definition node of the symbol.
    4. Returns the code of the symbol definition node.
- Output: The source code of the symbol definition AST node

#### 2. **search_string** (`packages/crete/framework/tools/services/search_string.py`)

- Tool name: `search_string`
- Parameters:
    - `string` (string, required): The string to search
    - `file_or_directory_path` (string, optional): The target path to search the string. If it's not given, it'll search the whole codebase.
- Behavior:
    1. Uses `RipGrep` command line tool to find the **string use locations**.
    2. Returns the stdout of `RipGrep`
- Output: An array of locations (`file_path:line_number:code_snippet[\n...]`)

#### 3. **view_file** (`packages/crete/framework/tools/services/view_file.py`)

- Tool name: `view_file`
- Parameters:
    - `file_path` (string, required): The path of the file to view
    - `offset` (integer, optional): The start line number of read from
    - `limit` (integer, optional): The number of lines to read
- Output: The content of the file by given range (max lines: 1000 lines)

### File Editing Tools

#### 1. **view_function** (`packages/crete/framework/coder/services/minimal/__init__.py`)

- Tool name: `view_function`
- Parameters:
    - `function_name` (string, required): The name of the function
- Output: The source code of the function definition

#### 2. **edit_function** (`packages/crete/framework/coder/services/minimal/__init__.py`)

- Tool name: `edit_function`
- Parameters:
    - `function_name` (string, required): The name of the function to edit
    - `old_string` (string, required): The string to replace
    - `new_string` (string, required): The new string to replace the `old_string`
- Output: A message indicating whether the function was editied successfully

#### 3. **add_import_module** (`packages/crete/framework/tools/services/add_import_module.py`)

- Tool name: `add_import_module`
- Parameters:
    - `module_name` (string, required): The name of the module to import (e.g., `java.util.ArrayList`)
    - `file_path` (string, required): The target file to add the module import statement
- Output: A message indicating whether the module was added successfully

## Design Principles

- Modularity: Separate modules for fault localization, patch generation and feedback handling which are core components of Martian agent
- Extensibility: New tool calls can be easily added and tested by including them in the `tools` array, which is passed to the `run_react_agent` function
- Observability: All LLM request/response logs and some artifacts (e.g., generated patch) are stored in the `agent_output_directory` via `store_debug_file`
- Fault Tolerance: The agent should continue operating even if a fragile component, such as an LLM request or Language Server request, fails

## Reference

- https://github.com/google-gemini/gemini-cli/tree/main/docs