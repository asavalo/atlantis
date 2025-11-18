from pathlib import Path
from typing import List

from python_aixcc_challenge.language.types import Language
from tree_sitter import Node, Parser, Tree
from tree_sitter_language_pack import get_language

from crete.commons.utils import not_none
from crete.framework.language_parser.contexts import LanguageParserContext
from crete.framework.language_parser.models import Kind, LanguageNode
from crete.framework.language_parser.protocols import LanguageParserProtocol


class TreeSitterLanguageParser(LanguageParserProtocol):
    def __init__(self, language: Language):
        self.language: Language = language

    def parse(self, context: LanguageParserContext, file: Path) -> Tree:
        assert file.exists(), f"File {file} does not exist"

        code = file.read_text(errors="replace")
        parser = _get_parser_by_language(self.language)
        return parser.parse(bytes(code, "utf-8"))

    def get_declarations_in_file(
        self, context: LanguageParserContext, file: Path
    ) -> list[tuple[str, LanguageNode]]:
        tree = self.parse(context, file)
        declarations: list[tuple[str, LanguageNode]] = []

        _find_declarations(
            self.language, file, tree.root_node, prefix="", declarations=declarations
        )

        match self.language:
            case "jvm":
                return declarations
            case "c" | "cpp" | "c++":
                file_lines = file.read_text(errors="replace").splitlines()
                additional_function_declarations = (
                    find_function_declarations_by_brace_analysis(
                        self, context, file, file_lines
                    )
                )
                return patch_declarations(
                    declarations, additional_function_declarations
                )

    def get_blocks_in_file(
        self, context: LanguageParserContext, file: Path
    ) -> List[LanguageNode]:
        tree = self.parse(context, file)
        blocks: List[LanguageNode] = []
        _find_blocks(self.language, file, tree.root_node, blocks=blocks)
        return blocks

    def get_identifier_of_declaration(
        self, context: LanguageParserContext, file: Path, node: LanguageNode
    ) -> LanguageNode | None:
        assert node.kind in [Kind.FUNCTION, Kind.CLASS, Kind.VARIABLE]
        tree = self.parse(context, file)
        declaration = _find_tree_sitter_node(tree.root_node, node)
        assert declaration is not None, f"Tree-sitter node not found for {node}"

        identifier = _get_identifier_of_declaration(declaration)
        if identifier is None:
            return None
        return _create_language_node(Kind.IDENTIFIER, identifier, file)

    # It returns string not LanguageNode because tree-sitter node is not sufficient to
    # represent the type of the declaration. For example, `char *buff` is parsed to
    # `char` type declaration with pointer declarator.
    def get_type_string_of_declaration(
        self, context: LanguageParserContext, file: Path, node: LanguageNode
    ) -> str | None:
        assert node.kind in [Kind.FUNCTION, Kind.CLASS, Kind.VARIABLE]
        tree = self.parse(context, file)
        declaration = _find_tree_sitter_node(tree.root_node, node)
        assert declaration is not None, f"Tree-sitter node not found for {node}"

        match self.language:
            case "c" | "cpp" | "c++":
                return _get_type_string_of_declaration_for_c(declaration, node.kind)
            case "jvm":
                return _get_type_string_of_declaration_for_java(declaration, node.kind)


def _get_parser_by_language(language: Language) -> Parser:
    parser = Parser()
    match language:
        case "c":
            parser.language = get_language("c")
        case "cpp" | "c++":
            parser.language = get_language("cpp")
        case "jvm":
            parser.language = get_language("java")

    return parser


def _find_declarations(
    language: Language,
    file: Path,
    node: Node,
    prefix: str,
    declarations: list[tuple[str, LanguageNode]],
) -> tuple[str, LanguageNode] | None:
    match language:
        case "c" | "cpp" | "c++":
            declaration = _find_declaration_for_c(file, node, prefix)
        case "jvm":
            declaration = _find_declaration_for_java(file, node, prefix)

    if declaration is not None:
        declarations.append(declaration)

        if declaration[1].kind == Kind.CLASS:
            prefix = declaration[0] + "."

    for child in node.children:
        _find_declarations(
            language,
            file,
            child,
            prefix,
            declarations,
        )

    return declaration


def _find_declaration_for_c(
    file: Path, node: Node, prefix: str
) -> tuple[str, LanguageNode] | None:
    def _get_name(node: Node, prefix: str) -> str | None:
        identifier_node = _get_identifier_of_declaration(node)
        if identifier_node is None:
            return None
        node_name = not_none(identifier_node.text).decode("utf-8")

        match node.type:
            case "function_definition" | "field_declaration":
                return prefix + node_name
            case (
                # Type Definitions
                "class_specifier"
                | "struct_specifier"
                | "union_specifier"
                | "enum_specifier"
                | "type_definition"
                # | "macro_type_specifier"
                # | "sized_type_specifier"
                # Function Declarations
                # | "function_declarator"
                # | "function_type_declarator"
                # Variable & Field Declarations
                | "declaration"
                # | "init_declarator"
                # | "pointer_declarator"
                | "array_declarator"
                # | "bitfield_clause"
                # Parameter Declarations (Treated as Variables)
                | "parameter_declaration"
                | "optional_parameter_declaration"
                | "parameter_list"
                # | "variadic_parameter"
                | "pointer_declarator"
                | "identifier"
                | "init_declarator"
            ):
                return node_name
            case _:
                raise ValueError(f"Unsupported node type {node.type}")

    node_type_to_kind = {
        # Type Definitions
        "class_specifier": Kind.CLASS,  # (Class declaration)
        "struct_specifier": Kind.TYPE_DEFINITION,  # (Struct declaration)
        "union_specifier": Kind.TYPE_DEFINITION,  # (Union declaration)
        "enum_specifier": Kind.TYPE_DEFINITION,  # (Enum declaration)
        "type_definition": Kind.TYPE_DEFINITION,  # (Typedef declaration)
        # "macro_type_specifier": Kind.TYPE_DEFINITION,     # (Macro-based type specification)
        # "sized_type_specifier": Kind.TYPE_DEFINITION,     # (Sized type specifier, e.g., long, short)
        # Function Definitions & Declarations
        "function_definition": Kind.FUNCTION,  # (Function definition)
        # "function_declarator": Kind.FUNCTION,             # (Function declarator)
        # "function_type_declarator": Kind.FUNCTION,        # (Function type declarator)
        # Variable & Field Declarations
        "field_declaration": Kind.VARIABLE,  # (Field declaration within a struct/class)
        "declaration": Kind.VARIABLE,  # (General variable declaration)
        "array_declarator": Kind.VARIABLE,  # (Array declaration)
        # "bitfield_clause": Kind.VARIABLE,                 # (Bitfield declaration)
        # Parameter Declarations  - Not kind.PARAMETER ?
        "parameter_declaration": Kind.VARIABLE,  # (Function parameter declaration)
        "optional_parameter_declaration": Kind.VARIABLE,  # (Optional function parameter declaration)
        "parameter_list": Kind.VARIABLE,  # (List of function parameters)
        # "variadic_parameter": Kind.VARIABLE,             # (Variadic parameter, e.g., "...")
        # "pointer_declarator": Kind.VARIABLE,
        "identifier": Kind.IDENTIFIER,
        # "init_declarator": Kind.VARIABLE,
    }

    # Handle standard node types
    if node.type in node_type_to_kind.keys():
        if _skip_node_for_c(node):
            return None
        kind = node_type_to_kind[node.type]
        name = _get_name(node, prefix)
        if name is not None:
            return name, _create_language_node(kind, node, file)


def _skip_node_for_c(node: Node) -> bool:
    if (
        node.type == "struct_specifier"
        and node.parent
        and node.parent.type == "type_definition"
    ):
        return True

    # For identifier / declarator
    if node.type == "identifier":
        if node.parent:
            match node.parent.type:
                case "pointer_declarator":
                    if node.parent.parent and node.parent.parent.type == "declaration":
                        return False
                case "init_declarator":
                    if node.parent.parent and node.parent.parent.type == "declaration":
                        return False
                case "declaration":
                    return False
                case _:
                    return True
        else:
            return True
    return False


def _find_declaration_for_java(
    file: Path, node: Node, prefix: str
) -> tuple[str, LanguageNode] | None:
    def _get_name(node: Node, prefix: str) -> str | None:
        identifier_node = _get_identifier_of_declaration(node)
        if identifier_node is None:
            return None
        node_name = not_none(identifier_node.text).decode("utf-8")
        match node.type:
            case (
                "class_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "field_declaration"
            ):
                return prefix + node_name
            case "formal_parameter" | "local_variable_declaration":
                return node_name
            case _:
                raise ValueError(f"Unsupported node type {node.type}")

    node_type_to_kind = {
        "constructor_declaration": Kind.FUNCTION,
        "method_declaration": Kind.FUNCTION,
        "class_declaration": Kind.CLASS,
        "field_declaration": Kind.VARIABLE,
        "formal_parameter": Kind.VARIABLE,
        "local_variable_declaration": Kind.VARIABLE,
    }

    if node.type in node_type_to_kind.keys():
        kind = node_type_to_kind[node.type]
        name = _get_name(node, prefix)
        if name is not None:
            return name, _create_language_node(kind, node, file)


def _find_blocks(
    language: Language, file: Path, node: Node, blocks: List[LanguageNode]
):
    match language:
        case "c" | "cpp" | "c++":
            block = _find_block_for_c(file, node)
        case "jvm":
            block = _find_block_for_java(file, node)

    if block is not None:
        blocks.append(block)

    for child in node.children:
        _find_blocks(language, file, child, blocks)
    return block


def _find_block_for_c(file: Path, node: Node) -> LanguageNode | None:
    if node.type == "compound_statement":
        return _create_language_node(Kind.BLOCK, node, file)
    return None


def _find_block_for_java(file: Path, node: Node) -> LanguageNode | None:
    if node.type == "block":
        return _create_language_node(Kind.BLOCK, node, file)
    return None


def _find_tree_sitter_node(tree: Node, language_node: LanguageNode) -> Node | None:
    for child in tree.children:
        if (
            child.start_point[0] == language_node.start_line
            and child.start_point[1] == language_node.start_column
            and child.end_point[0] == language_node.end_line - 1
            and child.end_point[1] == language_node.end_column
        ):
            return child

        result = _find_tree_sitter_node(child, language_node)
        if result is not None:
            return result
    return None


def _get_identifier_of_declaration(node: Node) -> Node | None:
    def _find_identifier_recursively(node: Node) -> Node | None:
        if node.type.endswith("identifier"):
            return node
        declarator_node = node.child_by_field_name("declarator")
        if declarator_node:
            return _find_identifier_recursively(declarator_node)

        for child in node.children:
            result = _find_identifier_recursively(child)
            if result is not None:
                return result
        return None

    return node.child_by_field_name("name") or _find_identifier_recursively(node)


def _get_type_string_of_declaration_for_c(declaration: Node, kind: Kind) -> str | None:
    match kind:
        case Kind.FUNCTION | Kind.CLASS:
            # TODO: Handle function type
            return None
        case Kind.VARIABLE:
            type_node = declaration.child_by_field_name("type")
            if type_node is None:
                assert type_node is not None, f"Type node not found for {declaration}"
            type_string = not_none(type_node.text).decode("utf-8")
            if _is_pointer_declaration_for_c(declaration):
                type_string += " *"
            return type_string
        case _:
            raise ValueError(f"Unsupported kind {kind}")


def _is_pointer_declaration_for_c(node: Node) -> bool:
    identifier_node = _get_identifier_of_declaration(node)
    if identifier_node is None:
        # Special case for anonymous function parameter
        # E.g.) int (*xToken)(void*, int, const char*, int nToken, int iStart, int iEnd)
        declarator_node = node.child_by_field_name("declarator")
        return bool(
            node.type == "parameter_declaration"
            and declarator_node is not None
            and declarator_node.type == "abstract_pointer_declarator"
        )

    return bool(
        identifier_node.parent and identifier_node.parent.type == "pointer_declarator"
    )


def _get_type_string_of_declaration_for_java(
    declaration: Node, kind: Kind
) -> str | None:
    match kind:
        case Kind.FUNCTION | Kind.CLASS:
            return None
        case Kind.VARIABLE:
            type_node = declaration.child_by_field_name("type")
            assert type_node is not None, f"Type node not found for {declaration}"
            return not_none(type_node.text).decode("utf-8")
        case _:
            raise ValueError(f"Unsupported kind {kind}")


def _create_language_node(kind: Kind, node: Node, file: Path) -> LanguageNode:
    return LanguageNode(
        kind=kind,
        start_line=node.start_point[0],
        start_column=node.start_point[1],
        end_line=node.end_point[0] + 1,
        end_column=node.end_point[1],
        file=file,
        text=not_none(node.text).decode("utf-8", errors="replace"),
    )


class PreprocessorAnalyzer:
    def __init__(self, file_lines: list[str]):
        self.file_lines = file_lines
        self.directive_stack_map: dict[int, list[tuple[str, int, int]]] = {}
        self.analyze()

    def analyze(self):
        current_stack: list[tuple[str, int, int]] = []
        leaf_counters: dict[int, int] = {}

        for i, line in enumerate(self.file_lines):
            line = line.strip()
            if not line.startswith("#"):
                self.directive_stack_map[i] = current_stack.copy()
                continue

            directive = line.split()[0] if " " in line else line

            if directive in ["#if", "#ifdef", "#ifndef"]:
                depth = len(current_stack)
                leaf_counters[depth] = 0
                current_stack.append((directive, i, 0))
            elif directive in ["#else", "#elif"]:
                if current_stack:
                    depth = len(current_stack) - 1
                    opening_directive, opening_line, _ = current_stack.pop()
                    leaf_counters[depth] += 1
                    current_stack.append(
                        (opening_directive, opening_line, leaf_counters[depth])
                    )
            elif directive == "#endif":
                if current_stack:
                    depth = len(current_stack) - 1
                    current_stack.pop()
                    if depth in leaf_counters:
                        del leaf_counters[depth]

            self.directive_stack_map[i] = current_stack.copy()

    def get_stack_at_line(self, line_idx: int) -> list[tuple[str, int, int]]:
        if line_idx < 0 or line_idx >= len(self.file_lines):
            return []
        return self.directive_stack_map.get(line_idx, [])

    def get_earliest_directive_line(self, start_line: int, end_line: int) -> int | None:
        earliest_line = None

        for i in range(start_line, end_line + 1):
            stack = self.get_stack_at_line(i)
            if stack:
                stack_earliest = min(line for _, line, _ in stack)
                if earliest_line is None or stack_earliest < earliest_line:
                    earliest_line = stack_earliest

        return earliest_line


# Patch TreeSitter Bug


class BraceEntry:
    def __init__(self, line_idx: int, directive_stack: list[tuple[str, int, int]]):
        self.line_idx = line_idx
        self.directive_stack = directive_stack


class ContextState:
    def __init__(self):
        self.brace_stack: list[BraceEntry] = []
        self.in_single_quote = False
        self.in_double_quote = False
        self.in_multi_line_comment = False
        self.has_terminator = False
        self.current_line = ""
        self.position = 0

    def start_line(self, line: str):
        self.current_line = line
        self.position = 0

    def end_of_line(self) -> bool:
        return self.position >= len(self.current_line)

    def peek(self, n: int = 1) -> str:
        if self.position + n <= len(self.current_line):
            return self.current_line[self.position : self.position + n]
        return ""

    def consume(self, n: int = 1):
        self.position += n

    def process_line(self):
        while not self.end_of_line():
            self.process_char()

    def process_char(self):
        if self.end_of_line():
            return

        if self.in_multi_line_comment:
            if self.peek(2) == "*/":
                self.in_multi_line_comment = False
                self.consume(2)
            else:
                self.consume(1)
            return

        if self.peek(2) == "//":
            self.position = len(self.current_line)
            return

        if self.in_single_quote:
            if self.peek() == "'" and (
                self.position == 0 or self.current_line[self.position - 1] != "\\"
            ):
                self.in_single_quote = False
            self.consume()
            return

        if self.in_double_quote:
            if self.peek() == '"' and (
                self.position == 0 or self.current_line[self.position - 1] != "\\"
            ):
                self.in_double_quote = False
            self.consume()
            return

        if self.peek(2) == "/*":
            self.in_multi_line_comment = True
            self.consume(2)
            return

        if self.peek() == "'":
            self.in_single_quote = True
            self.consume()
            return

        if self.peek() == '"':
            self.in_double_quote = True
            self.consume()
            return

        if self.peek() == ";" or self.peek() == "}":
            self.has_terminator = True
            self.consume()
            return

        self.consume()

    def append_brace_if_zero_leaf(self, entry: BraceEntry):
        if all(directive[2] == 0 for directive in entry.directive_stack):
            self.brace_stack.append(entry)

    def pop_brace_if_zero_leaf(
        self, current_directive_stack: list[tuple[str, int, int]]
    ) -> BraceEntry | None:
        if not self.brace_stack:
            return None

        if all(directive[2] == 0 for directive in current_directive_stack):
            return self.brace_stack.pop()

        return None


def find_root_compound_blocks(file_lines: list[str]) -> list[tuple[int, int]]:
    brace_pairs: list[tuple[int, int]] = []
    context = ContextState()
    preprocessor_analyzer = PreprocessorAnalyzer(file_lines)

    for i in range(len(file_lines)):
        line = file_lines[i].strip()

        if line.startswith("#"):
            continue

        context.start_line(line)

        while not context.end_of_line():
            if (
                context.in_multi_line_comment
                or context.in_single_quote
                or context.in_double_quote
                or context.peek(2) == "//"
                or context.peek(2) == "/*"
                or context.peek() == "'"
                or context.peek() == '"'
            ):
                context.process_char()
                continue

            if context.peek() == "{":
                directive_stack = preprocessor_analyzer.get_stack_at_line(i)
                entry = BraceEntry(i, directive_stack)
                context.append_brace_if_zero_leaf(entry)
                context.consume()
            elif context.peek() == "}":
                directive_stack = preprocessor_analyzer.get_stack_at_line(i)
                entry = context.pop_brace_if_zero_leaf(directive_stack)
                if entry is not None and not context.brace_stack:
                    brace_pairs.append((entry.line_idx, i))
                context.consume()
            else:
                context.consume()

    return brace_pairs


def mapping_brace_to_function(
    file_lines: list[str], brace_pairs: list[tuple[int, int]]
) -> dict[tuple[int, int], str]:
    function_map: dict[tuple[int, int], str] = {}
    preprocessor_analyzer = PreprocessorAnalyzer(file_lines)

    for brace_start, end_line in brace_pairs:
        stack = preprocessor_analyzer.get_stack_at_line(brace_start)
        if not all(directive[2] == 0 for directive in stack):
            continue

        context_lines = 10
        block_start = max(0, brace_start - context_lines)

        function_name = None
        function_start_line = None

        for i in range(block_start, brace_start + 1):
            line = file_lines[i].strip()

            if not line or line.startswith("#"):
                continue

            current_stack = preprocessor_analyzer.get_stack_at_line(i)
            if not all(directive[2] == 0 for directive in current_stack):
                continue

            context = ContextState()
            context.start_line(line)

            paren_pos = -1
            paren_found = False

            while not context.end_of_line():
                if (
                    context.in_multi_line_comment
                    or context.in_single_quote
                    or context.in_double_quote
                    or context.peek(2) == "//"
                    or context.peek(2) == "/*"
                    or context.peek() == "'"
                    or context.peek() == '"'
                ):
                    context.process_char()
                    continue

                if context.peek() == "(":
                    paren_pos = context.position
                    paren_found = True
                    break

                context.process_char()

            if paren_found and paren_pos > 0:
                before_paren = line[:paren_pos].strip()
                words = before_paren.split()
                if words:
                    candidate = words[-1]
                    if candidate and candidate.isidentifier():
                        function_name = candidate
                        function_start_line = i

        if function_name and function_start_line is not None:
            function_map[(function_start_line, end_line)] = function_name

    return function_map


def find_function_declarations_by_brace_analysis(
    parser: TreeSitterLanguageParser,
    context: LanguageParserContext,
    file: Path,
    file_lines: list[str],
) -> list[tuple[str, LanguageNode]]:
    function_declarations: list[tuple[str, LanguageNode]] = []

    try:
        parser_instance = _get_parser_by_language(parser.language)

        brace_pairs = find_root_compound_blocks(file_lines)
        function_map = mapping_brace_to_function(file_lines, brace_pairs)

        for (function_start_line, end_line), function_name in function_map.items():
            # Collect text from function declaration start to closing brace
            block_text = "\n".join(file_lines[function_start_line : end_line + 1])

            try:
                mini_tree = parser_instance.parse(bytes(block_text, "utf-8"))

                is_function = False
                if mini_tree.root_node.type == "function_definition":
                    is_function = True
                else:
                    for child in mini_tree.root_node.children:
                        if child.type == "function_definition":
                            is_function = True
                            break

                if is_function or "{" in block_text and "}" in block_text:
                    function_node = LanguageNode(
                        kind=Kind.FUNCTION,
                        start_line=function_start_line,
                        start_column=0,
                        end_line=end_line + 1,
                        end_column=len(file_lines[end_line])
                        if end_line < len(file_lines)
                        else 0,
                        file=file,
                        text=block_text.strip(),
                    )
                    function_declarations.append((function_name, function_node))

            except SyntaxError as e:
                print(
                    f"Syntax error parsing block at lines {function_start_line}-{end_line}: {e}"
                )
            except ValueError as e:
                print(
                    f"Value error processing block at lines {function_start_line}-{end_line}: {e}"
                )

    except TypeError as e:
        print(f"Type error in find_function_declarations_by_brace_analysis: {e}")
    except ValueError as e:
        print(f"Value error in find_function_declarations_by_brace_analysis: {e}")
    except KeyError as e:
        print(f"Key error in find_function_declarations_by_brace_analysis: {e}")
    except IOError as e:
        print(f"IO error in find_function_declarations_by_brace_analysis: {e}")

    return function_declarations


def patch_declarations(
    original_declarations: list[tuple[str, LanguageNode]],
    enhanced_declarations: list[tuple[str, LanguageNode]],
) -> list[tuple[str, LanguageNode]]:
    original_dict: dict[tuple[str, Kind, Path], list[tuple[str, LanguageNode]]] = {}
    for name, node in original_declarations:
        key = (name, node.kind, node.file)
        if key not in original_dict:
            original_dict[key] = []
        original_dict[key].append((name, node))

    improved_dict: dict[tuple[str, Kind, Path], LanguageNode] = {}
    for name, node in enhanced_declarations:
        key = (name, node.kind, node.file)
        if key not in improved_dict or len(node.text) > len(improved_dict[key].text):
            improved_dict[key] = node

    final_declarations: list[tuple[str, LanguageNode]] = []

    for key, declarations in original_dict.items():
        name = key[0]

        if key in improved_dict:
            improved_node = improved_dict[key]

            largest_original_node = max(declarations, key=lambda x: len(x[1].text))[1]

            if len(improved_node.text) > len(largest_original_node.text) * 1.2:
                final_declarations.append((name, improved_node))
                del improved_dict[key]
            else:
                final_declarations.extend(declarations)
        else:
            final_declarations.extend(declarations)

    for key, node in improved_dict.items():
        name = key[0]
        final_declarations.append((name, node))

    return final_declarations
