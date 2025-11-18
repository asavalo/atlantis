import re
import shlex
from dataclasses import dataclass
from pathlib import Path

from python_oss_fuzz.language_server_protocol.models import Location, SymbolInformation
from python_ripgrep import RIPGREP_EXECUTABLE_FILE

from crete.atoms.detection import Detection
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.commons.interaction.functions import run_command
from crete.commons.logging.hooks import use_logger
from crete.framework.code_inspector.contexts import CodeInspectorContext
from crete.framework.environment.functions import resolve_project_path
from crete.framework.language_parser.functions import get_declaration_by_line
from crete.framework.language_parser.models import Kind, LanguageNode

_logger = use_logger("code_inspector")


@dataclass
class SymbolLocation:
    file: Path
    line: int
    column: int


def search_symbol_in_codebase(
    context: CodeInspectorContext, symbol_name: str
) -> LanguageNode | None:
    match context["language_parser"].language:
        case "c" | "c++" | "cpp":
            return search_symbol_in_codebase_c(context, symbol_name)
        case "jvm":
            return search_symbol_in_codebase_java(context, symbol_name)


def _find_ast_node_for_symbol(
    context: CodeInspectorContext,
    symbol_def_location: Location,
    declaration_symbol_name: str,
) -> LanguageNode | None:
    # NOTE: LSP doesn't specify the kind of the symbol, so we need to check
    # all possible kinds. We'll start with the most specific kind and work
    # our way up
    # FIXME: This is not a good way to do this. Instead, we could use the
    # declaration name (symbol_def[0]) and compare with the symbol name.
    for kind in [Kind.VARIABLE, Kind.FUNCTION, Kind.TYPE_DEFINITION, Kind.CLASS]:
        symbol_def = get_declaration_by_line(
            context["language_parser"],
            context,
            symbol_def_location.file,
            symbol_def_location.range.start.line,
            kinds=[kind],
        )
        # This is for the case where another node is found earlier than desired.
        # For example, if we want to find the function definition but the parameter
        # declaration could be found earlier.
        #   8 | ...
        #   9 | public static void executeCommand(String data) {  // <- LSP found this
        #  10 | ...
        # Without this check, it will return `String data` as the symbol
        # definition of `executeCommand`.
        if symbol_def is not None and declaration_symbol_name in symbol_def[1].text:
            return symbol_def[1]
    context["logger"].warning(
        f"Could not find the AST node for {declaration_symbol_name}"
    )
    return None


def search_symbol_in_codebase_java(
    context: CodeInspectorContext, symbol_name: str
) -> LanguageNode | None:
    symbol_element_name_list = symbol_name.split(".")
    root_element_name = symbol_element_name_list.pop(0)

    root_element_use_locations = _find_symbol_locations_using_ripgrep(
        context, root_element_name
    )
    if len(root_element_use_locations) == 0:
        context["logger"].warning(
            " [RIPGREP] Failed to find the symbol: " + symbol_name
        )
        return None

    for root_element_use_location in root_element_use_locations:
        root_element_def_location = _find_symbol_def_location(
            context, root_element_use_location
        )
        if root_element_def_location is None:
            continue

        parent_element_name = root_element_name
        symbol_def_location = root_element_def_location
        document_symbols = context["lsp_client"].document_symbol(
            root_element_def_location.file
        )

        for element_name in symbol_element_name_list:
            element_symbol = _find_internal_symbol_in_given_symbol(
                document_symbols,  # type: ignore
                parent_element_name,
                element_name,
            )
            if element_symbol is None:
                continue

            symbol_def_location = element_symbol.location
            parent_element_name = element_name

        last_leaf_element_name = parent_element_name
        if node := _find_ast_node_for_symbol(
            context, symbol_def_location, last_leaf_element_name
        ):
            context["logger"].info(f"Found the symbol {symbol_name}: {node}")
            return node

    context["logger"].warning(f"Failed to find the symbol: {symbol_name}")
    return None


def _find_internal_symbol_in_given_symbol(
    document_symbols: list[SymbolInformation], parent_symbol: str, target_symbol: str
) -> SymbolInformation | None:
    for symbol in document_symbols:
        if (
            symbol.containerName.split("(")[0] == parent_symbol  # type: ignore
            and symbol.name.split("(")[0] == target_symbol
        ):
            return symbol
    return None


def search_symbol_in_codebase_c(
    context: CodeInspectorContext, symbol_name: str
) -> LanguageNode | None:
    symbol_use_locations = _find_symbol_locations_using_ripgrep(context, symbol_name)
    if len(symbol_use_locations) == 0:
        context["logger"].warning(
            " [RIPGREP] Failed to find the symbol: " + symbol_name
        )
        return None
    context["logger"].info(f"symbol use locations: {symbol_use_locations}")

    for symbol_use_location in symbol_use_locations:
        symbol_def_location = _find_symbol_def_location(context, symbol_use_location)
        if symbol_def_location is None:
            continue
        context["logger"].info(f"symbol def location: {symbol_def_location}")

        # NOTE: There's any subdefinition parsing logic in search_symbol_in_codebase_c
        # We'll need to implement additional parsing functionality for subclasses.
        if node := _find_ast_node_for_symbol(context, symbol_def_location, symbol_name):
            context["logger"].info(f"Found the symbol {symbol_name}: {node}")
            return node
    context["logger"].warning(f"Failed to find the symbol: {symbol_name}")
    return None


def _find_symbol_def_location(
    context: CodeInspectorContext, symbol_use_location: SymbolLocation
) -> Location | None:
    defs = context["lsp_client"].goto_definitions(
        symbol_use_location.file, symbol_use_location.line, symbol_use_location.column
    )
    context["logger"].debug(
        f"Found definitions at {symbol_use_location.file}:{symbol_use_location.line}:{symbol_use_location.column}: {[d for d in defs]}"
    )
    if len(defs) == 0:
        return None
    return defs[0]


def _find_symbol_locations_using_ripgrep(
    context: CodeInspectorContext, symbol_name: str
) -> list[SymbolLocation]:
    try:
        stdout, _stderr = run_command(
            (
                f"{RIPGREP_EXECUTABLE_FILE} -wHnF --max-count=100 {shlex.quote(symbol_name)} {context['pool'].source_directory}",
                Path("."),
            ),
        )
    except CommandInteractionError as e:
        _logger.warning(f"RIPGREP failed: {e}")
        return []

    locations: list[SymbolLocation] = []
    for line in stdout.strip().split("\n"):
        m = re.match(r"^(.*):(\d+):.*$", line)
        if m is None:
            continue

        file_path = Path(m.group(1))
        line_number = int(m.group(2)) - 1  # 0-based index

        column = _get_column_number_of_start_character_in_line(
            file_path, line_number, symbol_name
        )
        if column is None:
            continue

        locations.append(SymbolLocation(file_path, line_number, column))

    _logger.info(f"symbol use locations: {locations}")
    return locations


def get_function_definition_node(
    context: CodeInspectorContext,
    detection: Detection,
    file: Path,
    line: int,
    function_name: str,
) -> LanguageNode | None:
    resolved_path = resolve_project_path(file, context["pool"].source_directory)
    if resolved_path is None:
        return None
    column = _get_column_number_of_start_character_in_line(
        resolved_path, line, function_name
    )
    if column is None:
        return None

    defs = context["lsp_client"].goto_definitions(resolved_path, line, column)
    if len(defs) == 0:
        return None

    function_def_location = defs[0]
    function_def = get_declaration_by_line(
        context["language_parser"],
        context,
        function_def_location.file,
        function_def_location.range.start.line,
    )
    if function_def is None:
        return None
    return function_def[1]


def get_variable_type_definition_node(
    context: CodeInspectorContext,
    detection: Detection,
    file: Path,
    line: int,
    variable_name: str,
) -> LanguageNode | None:
    resolved_path = resolve_project_path(file, context["pool"].source_directory)
    if resolved_path is None:
        return None
    column = _get_column_number_of_start_character_in_line(
        resolved_path, line, variable_name
    )
    if column is None:
        return None

    defs = context["lsp_client"].goto_type_definitions(resolved_path, line, column)
    if len(defs) == 0:
        context["logger"].warning(
            f"Failed to find the type definition of {variable_name}"
        )
        return None

    variable_type_def_location = defs[0]
    variable_def = get_declaration_by_line(
        context["language_parser"],
        context,
        variable_type_def_location.file,
        variable_type_def_location.range.start.line,
        kinds=[Kind.TYPE_DEFINITION],
    )

    if variable_def is None:
        return None
    return variable_def[1]


def _get_column_number_of_start_character_in_line(
    file: Path, line: int, substring: str
) -> int | None:
    line_content = file.read_text(errors="replace").splitlines(keepends=True)[line]
    tab_count = 0
    for i in range(len(line_content)):
        if line_content[i] == "\t":
            tab_count += 1
        elif line_content[i:].startswith(substring):
            # FIXME: determine tab width
            return i - tab_count + (tab_count * 4)  # Assuming tab width of 4
    return None


def get_variable_declarations_in_function(
    context: CodeInspectorContext,
    function_node: LanguageNode,
) -> list[tuple[str, LanguageNode]]:
    parser = context["language_parser"]
    declarations = parser.get_declarations_in_file(context, function_node.file)
    variable_declarations: list[tuple[str, LanguageNode]] = []

    for name, declaration in declarations:
        if declaration.start_line < function_node.start_line:
            continue
        if declaration.end_line > function_node.end_line:
            continue
        if declaration.kind == Kind.VARIABLE:
            variable_declarations.append((name, declaration))

    return variable_declarations


def get_type_definition_of_variable(
    context: CodeInspectorContext,
    detection: Detection,
    variable_declaration: LanguageNode,
) -> LanguageNode | None:
    parser = context["language_parser"]
    identifier_node = parser.get_identifier_of_declaration(
        context, variable_declaration.file, variable_declaration
    )
    if identifier_node is None:
        context["logger"].warning("Identifier not found for variable")
        return None
    return get_variable_type_definition_node(
        context,
        detection,
        identifier_node.file,
        identifier_node.start_line,
        identifier_node.text,
    )


def search_string_in_source_directory(
    source_directory: Path, string: str, log_output: bool = True
) -> list[tuple[Path, int, str]]:
    """
    Search for a string in the codebase using ripgrep.

    Args:
        string: The string to search for.

    Returns:
        A list of tuples containing the file path, line number, and content of the string.
    """
    try:
        stdout, _stderr = run_command(
            (
                f"{RIPGREP_EXECUTABLE_FILE} -nF {shlex.quote(string)} {source_directory}",
                Path("."),
            ),
        )
    except CommandInteractionError as e:
        if log_output:
            _logger.warning(f"RIPGREP failed: {e}")
        return []

    results: list[tuple[Path, int, str]] = []
    for line in stdout.strip().split("\n"):
        if line:
            file, line_number, content = line.split(":", 2)
            if not line_number.isdigit():
                continue
            assert int(line_number) > 0, f"Invalid line number: {line_number}"
            # Convert to 0-based index
            results.append((Path(file), int(line_number) - 1, content))
    return results


def get_code_block_from_file(
    context: CodeInspectorContext,
    file: Path,
    start_line: int,
    end_line: int,
) -> str:
    resolved_path = resolve_project_path(file, context["pool"].source_directory)
    if resolved_path is None:
        return ""
    lines = resolved_path.read_text(errors="replace").splitlines(keepends=True)

    if (
        start_line <= 0
        or end_line <= 0
        or start_line > len(lines)
        or end_line > len(lines)
    ):
        return ""

    if start_line == end_line:
        return lines[start_line - 1]
    return "".join(lines[start_line - 1 : end_line - 1])
