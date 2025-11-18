from pathlib import Path

import pytest
from vuli.common.setting import Setting
from vuli.cp import CP
from vuli.debugger import Debugger


def test_basic_run():
    Setting().agent_path = (
        Path(__file__).parent.parent
        / "javaagent"
        / "target"
        / "java-agent-1.0-SNAPSHOT.jar"
    )
    Setting().root_dir = Path(__file__).parent.parent
    sample_cp: Path = Path(__file__).parent / "sample"
    sample_harness_out: Path = sample_cp / "out" / "harnesses" / "one"
    sample_harness_path: Path = (
        sample_cp
        / "src"
        / "sample-harness-one"
        / "src"
        / "main"
        / "java"
        / "sample"
        / "one"
        / "SampleOne.java"
    )
    jars: list[str] = [
        str(jar) for jar in sample_harness_out.iterdir() if str(jar).endswith(".jar")
    ]
    CP().harnesses = {
        "SampleOne": {
            "target_class": "sample.one.SampleOne",
            "classpath": jars,
            "src_path": str(sample_harness_path),
        }
    }
    debugger = Debugger()
    try:
        stdout: str = debugger.run(
            "SampleOne",
            b"\x00\x00\x00\x0A\x00\x00\x00\x01HELLO",
            ["stop go at sample.one.SampleOne.fuzzerTestOneInput"],
        )
        assert "The application exited" in stdout
        assert (
            len(
                [
                    line
                    for line in stdout.split("\n")
                    if line.startswith("Breakpoint hit:")
                    and "sample.one.SampleOne.fuzzerTestOneInput" in line
                ]
            )
            == 1
        )
    finally:
        debugger.stop()


@pytest.mark.timeout(15)
def test_timeout():
    Setting().agent_path = (
        Path(__file__).parent.parent
        / "javaagent"
        / "target"
        / "java-agent-1.0-SNAPSHOT.jar"
    )
    Setting().root_dir = Path(__file__).parent.parent
    sample_cp: Path = Path(__file__).parent / "sample"
    sample_harness_out: Path = sample_cp / "out" / "harnesses" / "one"
    sample_harness_path: Path = (
        sample_cp
        / "src"
        / "sample-harness-one"
        / "src"
        / "main"
        / "java"
        / "sample"
        / "one"
        / "SampleOne.java"
    )
    jars: list[str] = [
        str(jar) for jar in sample_harness_out.iterdir() if str(jar).endswith(".jar")
    ]
    CP().harnesses = {
        "SampleOne": {
            "target_class": "sample.one.SampleOne",
            "classpath": jars,
            "src_path": str(sample_harness_path),
        }
    }
    debugger = Debugger(timeout=5.0)
    try:
        stdout: str = debugger.run(
            "SampleOne",
            b"\x00\x00\x00\x0C\x00\x00\x00\x01HELLO",
            ["stop go at sample.one.SampleOne.fuzzerTestOneInput"],
        )
        assert (
            len(
                [
                    line
                    for line in stdout.split("\n")
                    if line.startswith("Breakpoint hit:")
                    and "sample.one.SampleOne.fuzzerTestOneInput" in line
                ]
            )
            == 1
        )
    finally:
        debugger.stop()
