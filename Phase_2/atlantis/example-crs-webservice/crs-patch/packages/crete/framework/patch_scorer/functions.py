import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, cast

from ordered_set import OrderedSet
from unidiff import PatchedFile, PatchSet

from crete.framework.environment.functions import resolve_project_path
from crete.framework.language_parser.functions import (
    get_declaration_by_line,
    get_declaration_by_name,
)
from crete.framework.patch_scorer.contexts import PatchScoringContext


def source_and_patched_declarations(
    context: PatchScoringContext,
    diff: str,
) -> Iterator[tuple[str | None, str | None]]:
    patch_set = PatchSet.from_string(diff)

    for patched_file in patch_set:
        source_file = resolve_project_path(
            Path(patched_file.source_file), context["pool"].source_directory
        )

        if source_file is None:
            raise ValueError(
                f"Could not resolve source file: {patched_file.source_file}"
            )

        partial_affected_source_line_numbers: set[int] = cast(set[int], OrderedSet([]))
        partial_affected_patched_line_numbers: set[int] = cast(set[int], OrderedSet([]))

        for hunk in patched_file:
            for line in hunk:
                if line.is_added:
                    assert line.source_line_no is None, "Source line number is not None"
                    assert line.target_line_no is not None, "Target line number is None"
                    partial_affected_patched_line_numbers.add(line.target_line_no)
                elif line.is_removed:
                    assert line.source_line_no is not None, "Source line number is None"
                    assert line.target_line_no is None, "Target line number is not None"
                    partial_affected_source_line_numbers.add(line.source_line_no)

        with _temporary_patched_file(patched_file, source_file) as patched_file:
            partial_affected_source_declarations = [
                _
                for _ in [
                    get_declaration_by_line(
                        context["language_parser"],
                        context,
                        source_file,
                        line_number,
                    )
                    for line_number in partial_affected_source_line_numbers
                ]
                if _ is not None
            ]

            partial_affected_patched_declarations = [
                _
                for _ in [
                    get_declaration_by_line(
                        context["language_parser"],
                        context,
                        patched_file,
                        line_number,
                    )
                    for line_number in partial_affected_patched_line_numbers
                ]
                if _ is not None
            ]

            affected_declarations = list(
                set(
                    [name for name, _ in partial_affected_source_declarations]
                    + [name for name, _ in partial_affected_patched_declarations]
                )
            )

            yield from [
                (
                    source[1].text if source is not None else source,
                    patched[1].text if patched is not None else patched,
                )
                for source, patched in [
                    (
                        get_declaration_by_name(
                            context["language_parser"], context, source_file, name
                        ),
                        get_declaration_by_name(
                            context["language_parser"], context, patched_file, name
                        ),
                    )
                    for name in affected_declarations
                ]
            ]


@contextmanager
def _temporary_patched_file(
    patch: PatchedFile,
    source_file: Path,
):
    with tempfile.NamedTemporaryFile(mode="w") as patch_file:
        patch_file.write(str(patch))
        patch_file.flush()

        patched_file = source_file.with_suffix(".patched")
        assert not patched_file.exists(), f"Patched file already exists: {patched_file}"

        try:
            subprocess.check_call(
                [
                    "patch",
                    "--out",
                    str(patched_file),
                    str(source_file),
                    patch_file.name,
                ],
            )

            yield patched_file

        finally:
            patched_file.unlink(missing_ok=True)
