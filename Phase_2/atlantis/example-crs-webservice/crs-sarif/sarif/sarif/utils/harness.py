import re
from pathlib import Path


def parse_jar_paths(harness_path: Path) -> list[Path]:
    try:
        with open(harness_path, "r") as f:
            content = f.read()

        cp_match = re.search(r"--cp=([^ ]+)", content)
        if not cp_match:
            return []

        classpath = cp_match.group(1)

        jar_paths = [path for path in classpath.split(":") if path]

        jar_paths.remove("$this_dir")
        jar_paths.remove(".")

        jar_paths = [
            path.replace("$this_dir", str(harness_path.parent)) for path in jar_paths
        ]

        return jar_paths
    except Exception as e:
        raise Exception(
            f"Error parsing harness jar paths from jazzer harness {harness_path}: {str(e)}"
        )
