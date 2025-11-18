from pathlib import Path
from typing import Any
from unittest.mock import patch

from vuli.struct import CodeLocation, CodePoint
from vuli.verifier import DebuggerVerifier, DebuggerVerifierCache


@patch("vuli.joern.Joern.run_query")
@patch("vuli.debugger.Debugger.stop")
@patch("vuli.debugger.Debugger.run")
def test_visited_for_path(patch_run, patch_stop, patch_run_query):
    def mock_stop(*args, **kwargs) -> None:
        pass

    def mock_run(*args, **kwargs) -> bool:
        return """
main[1] Deferring breakpoint Path:1.
It will be set after the class is loaded.
main[1] Deferring breakpoint Path:2.
It will be set after the class is loaded.
main[1] Deferring breakpoint Path:3.
It will be set after the class is loaded.

Breakpoint hit: "thread=main", Path.method(), line=1 bci=0
>
Breakpoint hit: "thread=main", Path.method(), line=2 bci=8
>
Breakpoint hit: "thread=main", Path.method(), line=3 bci=16
>
The application exited
"""

    def mock_run_query(*args, **kwargs) -> Any:
        if args[0].startswith("\ncpg"):
            return "path.java"
        else:
            return []

    patch_stop.side_effect = mock_stop
    patch_run.side_effect = mock_run
    patch_run_query.side_effect = mock_run_query
    DebuggerVerifierCache().class_to_file = {
        "Path": "path.java",
    }
    verifier = DebuggerVerifier()
    visited: list[CodeLocation] = verifier.visited_for_path(
        b"blob",
        Path("harness_path"),
        [
            CodePoint("path.java", "method", 1),
            CodePoint("path.java", "method", 2),
            CodePoint("path.java", "method", 3),
        ],
    )
    assert visited == [
        CodeLocation("path.java", 1),
        CodeLocation("path.java", 2),
        CodeLocation("path.java", 3),
    ]
