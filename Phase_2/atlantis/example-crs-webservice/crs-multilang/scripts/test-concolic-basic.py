#!/usr/bin/env python3

import json
from subprocess import run
from pathlib import Path
import os
import shutil
from typing import Dict, Any

TIMEOUT = 10 
CONFIG_FILE = Path("test-crs.json")

def write_config(config: Dict[str, Any]) -> Path:
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)
        return CONFIG_FILE

def main():
    timeout = TIMEOUT
    out_no_concolic = "./out-no-concolic"
    out_concolic = "./out-concolic"
    config = {
        "ncpu": 5,
        "others": {"input_gens": ["mock_input_gen"]},
    }
    config_file = write_config(config)
    cmdline = f"python3 run.py eval --target aixcc/c/concolic-test --config {str(config_file)} --seconds {timeout} --out {out_no_concolic}"
    run(cmdline, shell=True)

    config["others"]["input_gens"].append("concolic_input_gen")
    config_file = write_config(config)
    cmdline = f"python3 run.py eval --target aixcc/c/concolic-test --config {str(config_file)} --seconds {timeout} --out {out_concolic}"
    run(cmdline, shell=True)

    os.unlink(config_file)

    assert not list(
        (
            Path(out_no_concolic)
            / "aixcc/c/concolic-test/eval_result/povs/basic_harness"
        ).iterdir()
    )
    assert list(
        (
            Path(out_concolic) / "aixcc/c/concolic-test/eval_result/povs/basic_harness"
        ).iterdir()
    )

    shutil.rmtree(out_no_concolic)
    shutil.rmtree(out_concolic)


if __name__ == "__main__":
    main()
