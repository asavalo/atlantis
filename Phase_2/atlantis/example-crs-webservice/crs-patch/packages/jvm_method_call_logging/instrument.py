import os
import shutil
import subprocess
import glob
from pathlib import Path

JAVA_HOME = os.getenv("JAVA_HOME")

assert JAVA_HOME is not None

JAVA_PATH = Path(JAVA_HOME) / "bin" / "java"
INSTRUMENTER_JAR = "/work/method_call_logging/instrumenter/target/JarInstrumenter-1.0-SNAPSHOT-jar-with-dependencies.jar"
INSTRUMENT_TIMEOUT = 60 * 3
INSTRUMENT_WORK_PATH = Path("/work/method_call_logging/tmp")

INSTRUMENT_WORK_PATH.mkdir(parents=True, exist_ok=True)

for p in glob.glob("/out/**/*.jar", recursive=True):
    path = Path(p)
    if "jazzer" in path.name:
        continue

    p = subprocess.Popen(
        [
            JAVA_PATH,
            "-jar",
            INSTRUMENTER_JAR,
            str(path),
            str(INSTRUMENT_WORK_PATH / path.name),
        ]
    )

    try:
        stdout, stderr = p.communicate(timeout=INSTRUMENT_TIMEOUT)
    except subprocess.TimeoutExpired:
        print(f"Timeout : {path}")
        continue

    if p.returncode != 0:
        print(f"An error has been occurred during the instrumentation process : {path}")
        print(f"stdout: {stdout}")
        print(f"stderr: {stderr}")
        continue

    shutil.move(INSTRUMENT_WORK_PATH / path.name, path)
