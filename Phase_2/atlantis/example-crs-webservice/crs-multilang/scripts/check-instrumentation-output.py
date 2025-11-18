import argparse
import os
from pathlib import Path
import csv
import subprocess
from typing import List

def parse_args():
    parser = argparse.ArgumentParser(description="Check instrumentation output.")
    parser.add_argument(
        "--oss-fuzz-root",
        type=str,
        default=None,
        help="Path to the OSS fuzz root after running instrument-all command.",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output.csv",
        help="Path to the output CSV file.",
    )
    return parser.parse_args()


def check_oss_fuzz_root(oss_fuzz_root: Path):
    if not oss_fuzz_root.exists():
        raise FileNotFoundError(f"The path {oss_fuzz_root} does not exist.")
    if oss_fuzz_root.name != "oss-fuzz":
        raise ValueError(f"The path {oss_fuzz_root} is not the OSS fuzz root.")


def check_ldd_output(binary: Path):
    ldd_command = ["ldd", str(binary)]
    try:
        result = subprocess.run(ldd_command, capture_output=True, text=True, check=True)
        stdout = result.stdout
        if not "libsymcc-rt.so" in stdout:
            raise RuntimeError(
                f"libsymcc-rt.so not found in ldd output for {binary}: {stdout}"
            )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"ldd command failed: {e.stderr}")


def get_result(files: List[Path]):
    found_at_least_one = False

    for file in files: 
        if file.name == "llvm-symbolizer":
            continue
        if file.is_file() and os.access(file, os.X_OK):
            check_ldd_output(file)
            found_at_least_one = True
            break
    return found_at_least_one


def main():
    args = parse_args()

    if args.oss_fuzz_root is None:
        oss_fuzz_root = Path(__file__).parent.parent / "libs/oss-fuzz/"
    else:
        oss_fuzz_root = Path(args.oss_fuzz_root)

    check_oss_fuzz_root(oss_fuzz_root)
    rows = []
    out_dir = oss_fuzz_root / "build/out"
    project_dir = oss_fuzz_root / "projects"
    for root, _, files in out_dir.walk():
        project_name = "/".join(Path(root).relative_to(out_dir).parts)
        if (project_dir / project_name / "project.yaml").exists():
            result = get_result([root / x for x in files])
            rows.append({"Project": project_name, "Result": str(result)})
    if not rows:
        raise ValueError("No build projects found in the OSS fuzz root.")

    with open(args.output, "w", newline="") as csvfile:
        fieldnames = ["Project", "Result"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


if __name__ == "__main__":
    main()
