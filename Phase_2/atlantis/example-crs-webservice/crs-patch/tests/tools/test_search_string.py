import tempfile
from pathlib import Path
from unittest.mock import Mock

from crete.framework.tools.services import SearchStringTool


def test_search_string_too_many_matches():
    context = {"logger": Mock()}
    with tempfile.TemporaryDirectory() as temp_dir:
        for i in range(200):
            (Path(temp_dir) / f"file_{i}.txt").write_text("foo; bar;")

        tool = SearchStringTool(context, Path(temp_dir))  # pyright: ignore[reportArgumentType]
        ret = tool._run("foo")  # pyright: ignore[reportPrivateUsage]

    assert "foo; bar;" in ret, "Should find the string"
    assert ret.count("foo") < 200, "Should not return all matches"


def test_search_string_not_found():
    context = {"logger": Mock()}
    with tempfile.TemporaryDirectory() as temp_dir:
        tool = SearchStringTool(context, Path(temp_dir))  # pyright: ignore[reportArgumentType]
        ret = tool._run("foo")  # pyright: ignore[reportPrivateUsage]

    assert ret == "Not Found", "Should not find the string"


def test_search_string_in_codebase():
    context = {"logger": Mock()}
    with tempfile.TemporaryDirectory() as temp_dir:
        (Path(temp_dir) / "file1.txt").write_text("foo; bar;")
        (Path(temp_dir) / "file2.txt").write_text("foo; baz;")
        tool = SearchStringTool(context, Path(temp_dir))  # pyright: ignore[reportArgumentType]
        ret = tool._run("foo")  # pyright: ignore[reportPrivateUsage]

        assert sorted(ret.splitlines()) == sorted(
            ["file1.txt:1:foo; bar;", "file2.txt:1:foo; baz;"],
        ), "Should find the string"


def test_search_string_in_file():
    context = {"logger": Mock()}
    with tempfile.TemporaryDirectory() as temp_dir:
        target_file = Path(temp_dir) / "file.txt"
        target_file.write_text("foo; bar;")
        tool = SearchStringTool(context, Path(temp_dir))  # pyright: ignore[reportArgumentType]
        ret = tool._run("foo", target_file.as_posix())  # pyright: ignore[reportPrivateUsage]

    assert ret == "1:foo; bar;", "Should find the string"


def test_search_string_in_directory():
    context = {"logger": Mock()}
    with tempfile.TemporaryDirectory() as temp_dir:
        sub_dir = Path(temp_dir) / "sub_dir"
        sub_dir.mkdir()
        (sub_dir / "file1.txt").write_text("foo; bar;")
        (sub_dir / "file2.txt").write_text("foo; baz;")
        fake_dir = Path(temp_dir) / "fake_dir"
        fake_dir.mkdir()
        (fake_dir / "file3.txt").write_text("foo; boo;")
        tool = SearchStringTool(context, Path(temp_dir))  # pyright: ignore[reportArgumentType]
        ret = tool._run("foo", sub_dir.as_posix())  # pyright: ignore[reportPrivateUsage]
        assert sorted(ret.splitlines()) == sorted(
            ["file1.txt:1:foo; bar;", "file2.txt:1:foo; baz;"],
        ), "Should find the string"
