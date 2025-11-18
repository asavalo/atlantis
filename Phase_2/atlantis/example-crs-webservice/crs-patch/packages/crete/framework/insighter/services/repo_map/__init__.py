from pathlib import Path

from python_llm.api.actors import LlmApiManager

from crete.atoms.detection import Detection
from crete.framework.analyzer.services.repo_map import RepoMapAnalyzer
from crete.framework.insighter import InsighterContext, InsighterProtocol


class RepoMapInsighter(InsighterProtocol):
    def __init__(self, llm_api_manager: LlmApiManager, target_files: list[Path]):
        self._analyzer = RepoMapAnalyzer(llm_api_manager)
        self._target_files = target_files

    def create(
        self,
        context: InsighterContext,
        detection: Detection,
    ) -> str | None:
        return self._analyzer.analyze(
            context=context,
            detection=detection,
            target_files=self._target_files,
        )
