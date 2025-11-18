import subprocess
from pathlib import Path
from typing import cast

from langchain.output_parsers import BooleanOutputParser
from langchain_core.language_models.chat_models import BaseChatModel

from crete.framework.fault_localizer.models import FaultLocation


def fault_locations_to_files(
    fault_locations: list[FaultLocation],
) -> list[Path]:
    return list(set([fault_location.file for fault_location in fault_locations]))


def get_git_tracked_files(repo_path: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", repo_path, "ls-files"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        tracked_files = result.stdout.strip().splitlines()
        return [Path(file) for file in tracked_files]
    except subprocess.CalledProcessError:
        return []


def filter_out_common_functions(
    fault_locations: list[FaultLocation],
    model: BaseChatModel,
) -> list[FaultLocation]:
    """
    This function is under development and will be improved in the future. (#408)
    """
    start_index_of_non_common = 0
    for i, fault_location in enumerate(fault_locations):
        if not _is_common_fault_location(fault_location, model):
            start_index_of_non_common = i
            break
    return fault_locations[start_index_of_non_common:]


def _is_common_fault_location(
    fault_location: FaultLocation, model: BaseChatModel
) -> bool:
    parser = BooleanOutputParser()
    query = (
        f"Is this a common or utility function? {fault_location.function_name}\n"
        "Answer with yes or no with the reason."
    )
    response = model.invoke(query)
    return parser.parse(cast(str, response.content))  # type: ignore
