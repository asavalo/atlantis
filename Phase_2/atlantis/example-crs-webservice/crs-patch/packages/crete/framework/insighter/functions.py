from pathlib import Path

from crete.framework.insighter.contexts import InsighterContext


def make_relative_to_source_directory(context: InsighterContext, file: Path) -> Path:
    if file.is_relative_to(context["pool"].source_directory):
        return file.relative_to(context["pool"].source_directory)
    else:
        return file
