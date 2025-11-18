import importlib
import json
from glob import glob
from pathlib import Path
from typing import Dict, Iterator, List

import click


@click.command()
@click.argument(
    "detection-files",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    nargs=-1,
)
@click.option(
    "--module",
    "-m",
    help="""App to run ([module]:[object])""",
    required=False,
    default=None,
    multiple=True,
    type=str,
)
@click.option(
    "--github-action-output",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    default=Path(__file__).parent.parent.parent / "benchmark_multiple.json",
)
def main(
    detection_files: tuple[Path],
    module: list[str],
    github_action_output: Path,
):
    actions: List[tuple[str, Path]] = []
    output: List[Dict[str, str]] = []

    modules = (
        list(_all_modules())
        if len(module) == 0
        else [_verified_module(m) for m in module]
    )

    active_detection_files = list(
        filter(lambda x: not x.stem.startswith("_"), detection_files)
    )

    for app in modules:
        for detection in active_detection_files:
            actions.append((app, detection))

    for action in actions:
        app, detection = action
        output.append(
            {
                "target": str(detection),
                "module": app,
            }
        )
    github_action_output.write_text(json.dumps({"include": output}))


def _all_modules() -> Iterator[str]:
    for path in glob("apps/**/*.py", recursive=True):
        module_name = Path(path).stem
        if module_name.startswith("_") or module_name.startswith("."):
            continue
        module = path.removesuffix(".py").replace("/", ".")
        assert module.startswith("apps.")
        yield _verified_module(module)


def _verified_module(module: str) -> str:
    try:
        importlib.import_module(module)
    except ImportError:
        raise ValueError(f"Could not import module {module}")

    return module


if __name__ == "__main__":
    main()
