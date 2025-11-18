from pathlib import Path

from crete.framework.language_parser.contexts import LanguageParserContext
from crete.framework.language_parser.models import Kind, LanguageNode
from crete.framework.language_parser.protocols import LanguageParserProtocol


def get_declaration_by_line(
    parser: LanguageParserProtocol,
    context: LanguageParserContext,
    file: Path,
    line: int,
    kinds: list[Kind] = [Kind.FUNCTION, Kind.CLASS],
) -> tuple[str, LanguageNode] | None:
    return get_declaration_by_line_range(parser, context, file, (line, line + 1), kinds)


def get_declaration_by_line_range(
    parser: LanguageParserProtocol,
    context: LanguageParserContext,
    file: Path,
    range: tuple[int, int],
    kinds: list[Kind] = [Kind.FUNCTION, Kind.CLASS],
) -> tuple[str, LanguageNode] | None:
    lines = file.read_text(errors="replace").splitlines()
    if range[0] < 0 or range[1] < 0 or range[0] >= len(lines) or range[1] >= len(lines):
        return None
    return get_declaration_by_line_and_column_range(
        parser,
        context,
        file,
        (range[0], len(lines[range[0]]) - 1),
        (range[1], 0),
        kinds,
    )


def get_declaration_by_line_and_column_range(
    parser: LanguageParserProtocol,
    context: LanguageParserContext,
    file: Path,
    start_position: tuple[int, int],
    end_position: tuple[int, int],
    kinds: list[Kind] = [Kind.FUNCTION, Kind.CLASS],
) -> tuple[str, LanguageNode] | None:
    declarations = parser.get_declarations_in_file(context, file)

    # Find the declaration within the range and has the smallest span (i.e., the most specific one)
    try:
        in_range_declarations: list[tuple[str, LanguageNode]] = []
        for declaration in declarations:
            _name, declaration_node = declaration

            # Check if the declaration is outside the start position
            if declaration_node.start_line > start_position[0] or (
                declaration_node.start_line == start_position[0]
                and declaration_node.start_column > start_position[1]
            ):
                continue

            # Check if the declaration is outside the end position
            if declaration_node.end_line < end_position[0] or (
                declaration_node.end_line == end_position[0]
                and declaration_node.end_column < end_position[1]
            ):
                continue

            if declaration_node.kind not in kinds:
                continue

            in_range_declarations.append(declaration)

        # Return the line with the smallest delta first; if there is a tie,
        # return the column with the smallest delta.
        return min(
            in_range_declarations,
            key=lambda x: (
                x[1].end_line - x[1].start_line,
                x[1].end_column - x[1].start_column,
            ),
        )
    except ValueError:
        return None


def get_declaration_by_name(
    parser: LanguageParserProtocol,
    context: LanguageParserContext,
    file: Path,
    name: str,
    kinds: list[Kind] = [Kind.FUNCTION, Kind.CLASS],
) -> tuple[str, LanguageNode] | None:
    declarations = parser.get_declarations_in_file(context, file)
    for declaration_name, declaration in declarations:
        if name in declaration_name and declaration.kind in kinds:
            return declaration_name, declaration
    return None
