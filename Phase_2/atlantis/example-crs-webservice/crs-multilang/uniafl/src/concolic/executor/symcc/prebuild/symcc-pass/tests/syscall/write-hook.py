import json
from pathlib import Path


def main():
    hook_script = Path(__file__).parent / "hook.py"
    hook_json = Path(__file__).parent / "hook.json"

    with open(hook_script, "r") as f:
        python_code = f.read()
    hook = {
        "python_code": python_code,
    }
    with open(hook_json, "w") as f:
        json.dump(hook, f, indent=4)


if __name__ == "__main__":
    main()
