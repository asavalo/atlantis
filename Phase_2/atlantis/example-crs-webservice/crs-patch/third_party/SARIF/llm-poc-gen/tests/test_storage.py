import base64
import json
import tempfile
from pathlib import Path

import pytest
from vuli.common.setting import Storage, StorageDataStatus
from vuli.struct import CodePoint


@pytest.fixture(autouse=True)
def setup():
    Storage().clear()


def test_path():
    t = tempfile.NamedTemporaryFile()
    Storage().set_path(Path(t.name))
    Storage().add_path(
        "id_1",
        [CodePoint("path", "method", 0, 0)],
        ["cmdi"],
        StorageDataStatus.EXPLOITED,
    )
    Storage().save()
    with Path(t.name).open() as f:
        root = json.load(f)
        assert root.get("paths", {}) == [
            {
                "harness_id": "id_1",
                "route": [{"path": "path", "line": 0, "column": 0}],
                "bug_types": ["cmdi"],
                "status": "EXPLOITED",
            }
        ]


def test_path_multiple():
    t = tempfile.NamedTemporaryFile()
    Storage().set_path(Path(t.name))
    Storage().add_path(
        "id_1",
        [CodePoint("path_1", "method_1", 0, 5)],
        ["cmdi"],
        StorageDataStatus.EXPLOITED,
    )
    Storage().add_path(
        "id_2",
        [
            CodePoint("path_2", "method_2", 10, 15),
            CodePoint("path_3", "method_3", 20, 25),
        ],
        ["ssrf"],
        StorageDataStatus.NOT_REACHED,
    )
    Storage().save()
    with Path(t.name).open() as f:
        root = json.load(f)
        assert root.get("paths", {}) == [
            {
                "harness_id": "id_1",
                "route": [{"path": "path_1", "line": 0, "column": 5}],
                "bug_types": ["cmdi"],
                "status": "EXPLOITED",
            },
            {
                "harness_id": "id_2",
                "route": [
                    {"path": "path_2", "line": 10, "column": 15},
                    {"path": "path_3", "line": 20, "column": 25},
                ],
                "bug_types": ["ssrf"],
                "status": "NOT_REACHED",
            },
        ]


def test_sink():
    t = tempfile.NamedTemporaryFile()
    Storage().set_path(Path(t.name))
    Storage().add_sink("path", 0, 1, {"cmdi"})
    Storage().save()
    with Path(t.name).open() as f:
        assert json.load(f).get("sinks", {}) == [
            {
                "file_path": "path",
                "line": 0,
                "column": 1,
                "bug_types": ["cmdi"],
            }
        ]


def test_sink_multiple():
    t = tempfile.NamedTemporaryFile()
    Storage().set_path(Path(t.name))
    Storage().add_sink("path_1", 0, 1, {"cmdi"})
    Storage().add_sink("path_2", 2, 3, {"ssrf"})
    Storage().save()
    with Path(t.name).open() as f:
        assert json.load(f).get("sinks", {}) == [
            {
                "file_path": "path_1",
                "line": 0,
                "column": 1,
                "bug_types": ["cmdi"],
            },
            {
                "file_path": "path_2",
                "line": 2,
                "column": 3,
                "bug_types": ["ssrf"],
            },
        ]


def test_seed():
    t = tempfile.NamedTemporaryFile()
    Storage().clear()
    Storage().set_path(Path(t.name))
    Storage().add_seed("harness", b"blob")
    with Path(t.name).open() as f:
        result: list[dict] = json.load(f).get("result", [])
        assert result == [
            {
                "harness_id": "harness",
                "blob": [base64.b64encode(b"blob").decode("utf-8")],
            }
        ]


def test_seed_multiple():
    t = tempfile.NamedTemporaryFile()
    Storage().clear()
    Storage().set_path(Path(t.name))
    Storage().add_seed("harness_1", b"blob1")
    Storage().add_seed("harness_1", b"blob2")
    Storage().add_seed("harness_2", b"blob3")
    with Path(t.name).open() as f:
        result: list[dict] = json.load(f).get("result", [])
        assert result == [
            {
                "harness_id": "harness_1",
                "blob": [
                    base64.b64encode(b"blob1").decode("utf-8"),
                    base64.b64encode(b"blob2").decode("utf-8"),
                ],
            },
            {
                "harness_id": "harness_2",
                "blob": [base64.b64encode(b"blob3").decode("utf-8")],
            },
        ]


def test_all():
    t = tempfile.NamedTemporaryFile()
    Storage().clear()
    Storage().set_path(Path(t.name))
    Storage().add_sink("path_1", 0, 1, ["cmdi"])
    Storage().add_sink("path_2", 2, 3, ["ssrf"])
    Storage().add_sink("path_3", 4, 5, ["pt"])
    Storage().add_path(
        "harness_1",
        [CodePoint("path_1", "method_1", 0, 1)],
        ["cmdi"],
        StorageDataStatus.EXPLOITED,
    )
    Storage().add_path(
        "harness_2",
        [CodePoint("path_2", "method_2", 2, 3)],
        ["ssrf"],
        StorageDataStatus.NOT_REACHED,
    )
    Storage().add_path(
        "harness_3",
        [CodePoint("path_3", "method_3", 4, 5)],
        ["pt"],
        StorageDataStatus.REACHED,
    )
    Storage().add_seed("harness_1", b"blob1")
    Storage().add_seed("harness_1", b"blob2")
    Storage().add_seed("harness_2", b"blob3")
    Storage().add_seed("harness_3", b"blob4")
    Storage().save()
    with Path(t.name).open() as f:
        assert json.load(f) == {
            "sinks": [
                {
                    "file_path": "path_1",
                    "line": 0,
                    "column": 1,
                    "bug_types": ["cmdi"],
                },
                {
                    "file_path": "path_2",
                    "line": 2,
                    "column": 3,
                    "bug_types": ["ssrf"],
                },
                {
                    "file_path": "path_3",
                    "line": 4,
                    "column": 5,
                    "bug_types": ["pt"],
                },
            ],
            "paths": [
                {
                    "harness_id": "harness_1",
                    "route": [{"path": "path_1", "line": 0, "column": 1}],
                    "bug_types": ["cmdi"],
                    "status": "EXPLOITED",
                },
                {
                    "harness_id": "harness_2",
                    "route": [{"path": "path_2", "line": 2, "column": 3}],
                    "bug_types": ["ssrf"],
                    "status": "NOT_REACHED",
                },
                {
                    "harness_id": "harness_3",
                    "route": [{"path": "path_3", "line": 4, "column": 5}],
                    "bug_types": ["pt"],
                    "status": "REACHED",
                },
            ],
            "result": [
                {
                    "harness_id": "harness_1",
                    "blob": [
                        base64.b64encode(b"blob1").decode("utf-8"),
                        base64.b64encode(b"blob2").decode("utf-8"),
                    ],
                },
                {
                    "harness_id": "harness_2",
                    "blob": [base64.b64encode(b"blob3").decode("utf-8")],
                },
                {
                    "harness_id": "harness_3",
                    "blob": [base64.b64encode(b"blob4").decode("utf-8")],
                },
            ],
        }
