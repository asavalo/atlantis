from __future__ import annotations

import atexit
import base64
import logging
import shutil
import tempfile
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

import click
from joblib import Memory
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.language_server_protocol.actors import LspClient

from crete.atoms.action import Action
from crete.atoms.detection import BlobInfo, Detection
from crete.commons.logging.hooks import use_logger
from crete.framework.agent.contexts import AgentContext
from crete.framework.analyzer.services.call_trace import CallTraceAnalyzer
from crete.framework.analyzer.services.crash_log import CrashLogAnalyzer
from crete.framework.context_builder.protocols import ContextBuilderProtocol
from crete.framework.crete.models import Crete
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol
from crete.framework.environment_pool.services import OssFuzzEnvironmentPool
from crete.framework.evaluator.protocols import EvaluatorProtocol
from crete.framework.evaluator.services.cached import CachedEvaluator
from crete.framework.context_builder.models import SanitizerType
from crete.framework.language_parser.services.tree_sitter import (
    TreeSitterLanguageParser,
)


class AIxCCContextBuilder(ContextBuilderProtocol):
    def __init__(
        self,
        challenge_project_directory: Path,
        detection_toml_file: Path,
        cache_directory: Path | None = None,
        output_directory: Path | None = None,
        evaluator: EvaluatorProtocol | None = None,
        pool: EnvironmentPoolProtocol | None = None,
        logging_level: str | int = logging.INFO,
        max_timeout: int = 30 * 60,  # 30 minutes
        environment_pool_directory: Path | None = None,
    ) -> None:
        super().__init__()
        self._challenge_project_directory = challenge_project_directory
        self._detection_toml_file = detection_toml_file
        self._output_directory = output_directory
        self._evaluator = evaluator
        self._pool = pool
        self._logging_level = logging_level
        self._max_timeout = max_timeout
        self._environment_pool_directory = environment_pool_directory

        self._set_cache_directory(cache_directory)

    def _set_cache_directory(self, cache_directory: Path | None):
        if cache_directory is not None:
            self._cache_directory = cache_directory
        else:
            temp_directory = tempfile.mkdtemp()
            atexit.register(lambda: shutil.rmtree(temp_directory))
            self._cache_directory = Path(temp_directory)

    def _create_agent_output_directory(self) -> Path:
        agent_output_directory = (
            self._output_directory / f"agent-output-{str(time.time())}"
            if self._output_directory
            else Path(TemporaryDirectory(".crete").name)
            / f"agent-output-{str(time.time())}"
        )
        agent_output_directory.mkdir(parents=True, exist_ok=True)
        return agent_output_directory

    def build(
        self,
        previous_action: Action,
        reflection: str | None = None,
    ):
        challenge_project_detection = AIxCCChallengeProjectDetection.from_toml(
            self._detection_toml_file
        )
        challenge_project_yaml = AIxCCChallengeProjectYaml.from_project_name(
            challenge_project_detection.project_name
        )
        detection = Detection(
            mode=challenge_project_detection.mode,
            vulnerability_identifier=challenge_project_detection.vulnerability_identifier,
            project_name=challenge_project_detection.project_name,
            language=challenge_project_yaml.language,
            blobs=[
                BlobInfo(
                    harness_name=blob.harness_name,
                    sanitizer_name=blob.sanitizer_name,
                    blob=base64.b64decode(blob.blob),
                )
                for blob in challenge_project_detection.blobs
            ],
            sarif_report=challenge_project_detection.sarif_report_data,
        )

        agent_output_directory = self._create_agent_output_directory()

        sanitizer_name: SanitizerType = (
            cast(SanitizerType, detection.blobs[0].sanitizer_name)
            if detection.blobs
            else "address"
        )

        environment_context: EnvironmentContext = {
            "logger": use_logger(
                name=agent_output_directory.stem,
                level=self._logging_level,
            ),
            "logging_prefix": f"{detection.project_name}",
            "memory": Memory(self._cache_directory, verbose=0),
            "sanitizer_name": sanitizer_name,
        }

        for blob in detection.blobs:
            if not blob.sanitizer_name:
                environment_context["logger"].warning(  # just warning, not an error
                    f"sanitizer_name is required for blob {blob.harness_name}"
                )

        environment_context["logger"].info(
            (
                f"Building environment\n"
                f"- Cache directory: {self._cache_directory}\n"
                f"- Max timeout: {self._max_timeout}\n"
                f"- Output directory: {agent_output_directory}\n"
                f"- Detection toml file: {self._detection_toml_file}\n"
                f"- Challenge project directory: {self._challenge_project_directory}\n"
            )
        )

        if self._pool is None:
            self._pool = self._build_environment_pool(
                environment_context,
                challenge_project_detection,
                challenge_project_yaml,
            )

        context: AgentContext = {
            **environment_context,
            "pool": self._pool,
            "evaluator": self._evaluator or CachedEvaluator(),
            "previous_action": previous_action,
            "crash_log_analyzer": CrashLogAnalyzer(),
            "call_trace_snapshot": CallTraceAnalyzer(),
            "language_parser": TreeSitterLanguageParser(language=detection.language),
            "lsp_client": LspClient(
                detection.project_name,
                detection.language,
                self._challenge_project_directory,
            ),
            "output_directory": agent_output_directory,
        }

        if reflection:
            context["reflection"] = reflection

        return context, detection

    def _build_environment_pool(
        self,
        environment_context: EnvironmentContext,
        challenge_project_detection: AIxCCChallengeProjectDetection,
        challenge_project_yaml: AIxCCChallengeProjectYaml,
    ) -> EnvironmentPoolProtocol:
        pool = OssFuzzEnvironmentPool(
            challenge_project_directory=self._challenge_project_directory,
            challenge_project_detection=challenge_project_detection,
            challenge_project_yaml=challenge_project_yaml,
            max_timeout=self._max_timeout,
            cache_directory=self._environment_pool_directory,
        )

        pool.initialize(environment_context)
        return pool

    @staticmethod
    def shell(app: Crete):
        @click.command()
        @click.option(
            "--challenge-project-directory",
            "-cp",
            type=click.Path(
                exists=True, file_okay=False, dir_okay=True, path_type=Path
            ),
            required=True,
        )
        @click.option(
            "--detection-toml-file",
            "-d",
            type=click.Path(
                exists=True, file_okay=True, dir_okay=False, path_type=Path
            ),
            required=True,
        )
        @click.option(
            "--output-directory",
            "-o",
            type=click.Path(
                exists=True, file_okay=False, dir_okay=True, path_type=Path
            ),
            required=False,
            default=None,
        )
        @click.option(
            "--cache-directory",
            "-c",
            type=click.Path(
                exists=True, file_okay=False, dir_okay=True, path_type=Path
            ),
            required=False,
            default=None,
        )
        @click.option(
            "--timeout",
            type=int,
            default=5 * 60,  # 5 minutes
        )
        @click.option(
            "--llm-cost-limit",
            type=float,
            default=3,  # 3 dollars
        )
        def _(
            challenge_project_directory: Path,
            detection_toml_file: Path,
            output_directory: Path,
            cache_directory: Path,
            timeout: int,
            llm_cost_limit: float,
        ):
            app.run(
                context_builder=AIxCCContextBuilder(
                    challenge_project_directory=challenge_project_directory,
                    detection_toml_file=detection_toml_file,
                    output_directory=output_directory,
                    cache_directory=cache_directory,
                ),
                timeout=timeout,
                llm_cost_limit=llm_cost_limit,
                output_directory=output_directory,
            )

        return _()
