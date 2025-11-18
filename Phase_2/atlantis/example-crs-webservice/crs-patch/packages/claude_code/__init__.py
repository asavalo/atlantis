import subprocess
from pathlib import Path

CLAUDE_NVM_PATH = Path.home() / ".nvm-claude"

_claude_code_path: tuple[str, str] | None = None


def claude_code_path() -> tuple[str, str]:
    global _claude_code_path
    if _claude_code_path is not None:
        return _claude_code_path

    try:
        node_path, code_path = (
            subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{CLAUDE_NVM_PATH}/nvm.sh" && which node && which claude',
                ],
                check=True,
                text=True,
                capture_output=True,
            )
            .stdout.strip()
            .splitlines()
        )

        _claude_code_path = node_path, code_path
        return _claude_code_path
    except subprocess.CalledProcessError:
        raise FileNotFoundError(
            "Node.js isolated environment not found; run `./scripts/setup.py` to install it."
        )
