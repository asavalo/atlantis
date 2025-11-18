import os
import subprocess
from pathlib import Path
import sys

# --- Configuration ---
# Get the absolute path of the workspace root (assuming the script is run from the workspace root)
WORKSPACE_ROOT = (
    Path(__file__).resolve().parents[1]
)  # Go up two levels from scripts/batch_patch_to_sarif.py
BENCHMARK_DIR = WORKSPACE_ROOT / "benchmarks" / "matching"
GENERATOR_SCRIPT = WORKSPACE_ROOT / "sarif" / "scripts" / "generator.py"
PYTHON_EXECUTABLE = (
    sys.executable
)  # Use the same python interpreter that runs this script
# --- End Configuration ---


def find_diff_files(root_dir: Path) -> list[Path]:
    """Recursively finds all .diff files in the given directory."""
    diff_files = list(root_dir.rglob("*.diff"))
    print(f"Found {len(diff_files)} .diff files in {root_dir}")
    return diff_files


def convert_diff_to_sarif(diff_path: Path, script_path: Path):
    """Converts a single .diff file to .sarif using the generator script."""
    sarif_path = diff_path.with_suffix(".sarif")
    print(f"Processing: {diff_path} -> {sarif_path}")

    command = [
        PYTHON_EXECUTABLE,
        str(script_path),
        "run-with-patch",
        str(diff_path),
        str(sarif_path),
    ]

    try:
        # Use WORKSPACE_ROOT as the current working directory for the subprocess
        # This ensures that relative paths within generator.py (if any) work correctly.
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            cwd=WORKSPACE_ROOT,  # Set working directory
            encoding="utf-8",  # Ensure consistent encoding
        )
        print(f"  Success: {diff_path}")
        # print(f"  Output:\n{result.stdout}") # Uncomment for detailed stdout
        if result.stderr:
            print(f"  Stderr:\n{result.stderr}")  # Print stderr even on success
    except subprocess.CalledProcessError as e:
        print(f"  Failed: {diff_path}")
        print(f"  Return Code: {e.returncode}")
        print(f"  Command: {' '.join(e.cmd)}")  # Show the exact command run
        print(f"  Stdout:\n{e.stdout}")
        print(f"  Stderr:\n{e.stderr}")
    except FileNotFoundError:
        print(
            f"  Error: Could not find Python executable '{PYTHON_EXECUTABLE}' or script '{script_path}'. Please check paths."
        )
    except Exception as e:
        print(f"  An unexpected error occurred for {diff_path}: {e}")


def main():
    """Main function to find and convert all .diff files."""
    if not BENCHMARK_DIR.is_dir():
        print(f"Error: Benchmark directory not found: {BENCHMARK_DIR}")
        return
    if not GENERATOR_SCRIPT.is_file():
        print(f"Error: Generator script not found: {GENERATOR_SCRIPT}")
        return

    diff_files = find_diff_files(BENCHMARK_DIR)
    if not diff_files:
        print("No .diff files found to process.")
        return

    total_files = len(diff_files)
    for i, diff_file in enumerate(diff_files, 1):
        print(f"\n--- Processing file {i}/{total_files} ---")
        convert_diff_to_sarif(diff_file, GENERATOR_SCRIPT)

    print("\n--- Batch processing finished. ---")


if __name__ == "__main__":
    main()
