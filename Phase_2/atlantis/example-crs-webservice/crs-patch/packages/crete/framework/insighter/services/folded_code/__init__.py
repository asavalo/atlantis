from pathlib import Path

from python_aixcc_challenge.language.types import Language

from crete.atoms.detection import Detection
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.functions import make_relative_to_source_directory
from crete.framework.insighter.protocols import InsighterProtocol
from crete.framework.language_parser.models import Kind


class FoldedCodeInsighter(InsighterProtocol):
    """
    Provides a folded representation of the given file in the repository.
    """

    def __init__(self, file: Path):
        self._file = file

    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        intervals = sorted(
            [
                (declaration.start_line, declaration.end_line)
                for _, declaration in context[
                    "language_parser"
                ].get_declarations_in_file(context, self._file)
                if declaration.kind == Kind.FUNCTION  # Fold only functions
            ],
            key=lambda x: x[0],
        )

        lines = self._file.read_text(errors="replace").splitlines(keepends=True)
        updates: list[str | None] = [None] * len(lines)
        for interval in intervals:
            updates = _fold_declaration(detection.language, lines, updates, *interval)

        for i in range(len(lines)):
            if updates[i] is not None:
                lines[i] = str(updates[i])

        return f"""### File: {make_relative_to_source_directory(context, self._file)}

```{_get_language_identifier(detection.language)}
{"".join(lines)}
```
"""


def _update_lines(updates: list[str | None], lines: list[str], begin: int):
    for i in range(begin, begin + len(lines)):
        if updates[i] is None:
            # Update can happen only once
            updates[i] = lines[i - begin]
    return updates


def _delete_lines(updates: list[str | None], begin: int, end: int):
    for i in range(begin, end):
        updates[i] = ""
    return updates


def _fold_declaration(
    language: Language,
    lines: list[str],
    updates: list[str | None],
    begin: int,
    end: int,
) -> list[str | None]:
    original_length = len(lines)
    target_code = "".join(lines[begin:end])
    begin_delimiter, end_delimiter = _get_definition_delimiters(language)

    if begin_delimiter not in target_code or end_delimiter not in target_code:
        return updates

    folded_code = (
        target_code[: target_code.index(begin_delimiter) + 1]
        + "..."
        + target_code[target_code.rindex(end_delimiter) :]
    )

    new_lines = folded_code.splitlines(keepends=True)
    updates = _update_lines(updates, new_lines, begin)
    updates = _delete_lines(updates, begin + len(new_lines), end)
    assert len(lines) == original_length
    return updates


def _get_definition_delimiters(language: Language) -> tuple[str, str]:
    match language:
        case "c" | "cpp" | "c++" | "jvm":
            return "{", "}"


def _get_language_identifier(language: Language) -> str:
    match language:
        case "c":
            return "c"
        case "cpp" | "c++":
            return "cpp"
        case "jvm":
            return "java"
