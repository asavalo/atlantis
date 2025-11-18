from pathlib import Path

from crete.atoms.detection import Detection
from crete.framework.fault_localizer.functions import get_git_tracked_files
from crete.framework.insighter.contexts import InsighterContext
from crete.framework.insighter.protocols import InsighterProtocol


class RepositoryStructureInsighter(InsighterProtocol):
    def create(self, context: InsighterContext, detection: Detection) -> str | None:
        tracked_files = get_git_tracked_files(context["pool"].source_directory)
        current_directory = Path(".")

        insight = ""
        for file in tracked_files:
            current_directory, dump = _pretty_dump(current_directory, file)
            insight += dump

        return insight[:-1]  # Remove the last newline


def _pretty_dump(
    current_directory: Path, file: Path, dump: str = ""
) -> tuple[Path, str]:
    if file.parent == current_directory:
        return (
            current_directory,
            dump + "  " * len(current_directory.parts) + f"{file.name}\n",
        )
    else:
        if not file.is_relative_to(current_directory):
            return _pretty_dump(current_directory.parent, file, dump)
        else:
            sub_directory = file.relative_to(current_directory).parts[0]
            dump += "  " * len(current_directory.parts) + f"{sub_directory}/\n"
            current_directory = current_directory / sub_directory
            return _pretty_dump(current_directory, file, dump)
