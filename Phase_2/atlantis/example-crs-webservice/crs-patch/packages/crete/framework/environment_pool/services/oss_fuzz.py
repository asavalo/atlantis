import json
import time
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel
from python_aixcc_challenge.detection.models import AIxCCChallengeProjectDetection
from python_aixcc_challenge.project.models import AIxCCChallengeProjectYaml
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY

from crete.atoms.path import DEFAULT_CACHE_DIRECTORY
from crete.commons.logging.context_managers import logging_performance
from crete.framework.environment.contexts import EnvironmentContext
from crete.framework.environment.exceptions import ChallengeBuildFailedError
from crete.framework.environment.protocols import EnvironmentProtocol
from crete.framework.environment.services.oss_fuzz import (
    CachedOssFuzzEnvironment,
    CallTraceOssFuzzEnvironment,
    CDebugOssFuzzEnvironment,
    OssFuzzEnvironment,
    ValgrindOssFuzzEnvironment,
)
from crete.framework.environment_pool.functions import (
    load_environment,
    save_environment,
)
from crete.framework.environment_pool.models import EnvironmentType
from crete.framework.environment_pool.protocols import EnvironmentPoolProtocol


@dataclass
class EnvironmentDescriptor:
    tag: str
    type: EnvironmentType
    environment: EnvironmentProtocol


EnvironmentRedirection = dict[EnvironmentType, EnvironmentType]


@dataclass
class PoolDescriptor:
    base: OssFuzzEnvironment
    redirection: EnvironmentRedirection
    descriptors: list[EnvironmentDescriptor]


class Metadata(BaseModel):
    type_to_tag: dict[str, str]
    build_status: dict[str, bool]
    run_tests_status: bool
    measured_times: tuple[int, int] | None = None

    @staticmethod
    def read(
        cache_directory: Path,
        challenge_project_detection: AIxCCChallengeProjectDetection,
    ) -> "Metadata":
        metadata_file = (
            cache_directory / challenge_project_detection.project_name / "metadata.json"
        )
        if not metadata_file.exists():
            return Metadata(type_to_tag={}, build_status={}, run_tests_status=True)

        with open(metadata_file, "r") as f:
            return Metadata.model_validate(json.load(f))

    @staticmethod
    def write(
        cache_directory: Path,
        challenge_project_detection: AIxCCChallengeProjectDetection,
        metadata: "Metadata",
    ):
        metadata_file = (
            cache_directory / challenge_project_detection.project_name / "metadata.json"
        )
        metadata_file.parent.mkdir(parents=True, exist_ok=True)
        with open(metadata_file, "w") as f:
            json.dump(metadata.model_dump(), f)


class OssFuzzEnvironmentPool(EnvironmentPoolProtocol):
    def __init__(
        self,
        challenge_project_directory: Path,
        challenge_project_detection: AIxCCChallengeProjectDetection,
        challenge_project_yaml: AIxCCChallengeProjectYaml,
        max_timeout: int,
        cache_directory: Path | None = None,
    ):
        self._cache_directory = (
            cache_directory or DEFAULT_CACHE_DIRECTORY / "environments"
        )
        super().__init__(
            source_directory=challenge_project_directory.resolve(),
            work_directory=(
                OSS_FUZZ_DIRECTORY
                / "build"
                / "work"
                / challenge_project_detection.project_name
            ),
            project_directory=(
                OSS_FUZZ_DIRECTORY
                / "projects"
                / challenge_project_detection.project_name
            ),
            out_directory=(
                OSS_FUZZ_DIRECTORY
                / "build"
                / "out"
                / challenge_project_detection.project_name
            ),
        )

        self._challenge_project_detection = challenge_project_detection
        self._challenge_project_directory = challenge_project_directory
        self._challenge_project_yaml = challenge_project_yaml
        self._max_timeout = max_timeout

        self._environments: dict[EnvironmentType, tuple[str, EnvironmentProtocol]] = {}
        self._pool_descriptor = self._create_pool_descriptor()
        self._enable_tests = True

    def _create_pool_descriptor(
        self,
    ) -> PoolDescriptor:
        match self._challenge_project_yaml.language:
            case "c" | "c++" | "cpp":
                return self._create_pool_descriptor_for_c()
            case "jvm":
                return self._create_pool_descriptor_for_jvm()

    def _create_pool_descriptor_for_c(
        self,
    ) -> PoolDescriptor:
        base = OssFuzzEnvironment(
            pool=self,
            project_name=self._challenge_project_detection.project_name,
            checkout_ref=self._challenge_project_detection.mode.checkout_ref(),
            max_timeout=self._max_timeout,
        )

        debug = CDebugOssFuzzEnvironment(
            pool=self,
            environment=base,
            challenge_project_yaml=self._challenge_project_yaml,
        )

        cached = CachedOssFuzzEnvironment(
            pool=self,
            environment=base,
            challenge_project_yaml=self._challenge_project_yaml,
        )

        debug_cached = CDebugOssFuzzEnvironment(
            pool=self,
            environment=cached,
            challenge_project_yaml=self._challenge_project_yaml,
        )

        call_trace = CallTraceOssFuzzEnvironment(
            pool=self,
            environment=base,
            challenge_project_yaml=self._challenge_project_yaml,
            challenge_project_detection=self._challenge_project_detection,
        )

        valgrind = ValgrindOssFuzzEnvironment(
            pool=self,
            environment=base,
            challenge_project_yaml=self._challenge_project_yaml,
            challenge_project_detection=self._challenge_project_detection,
        )

        return PoolDescriptor(
            base=base,
            redirection={},
            descriptors=[
                EnvironmentDescriptor(
                    tag="Debug+Cached", type="DEBUG", environment=debug_cached
                ),
                EnvironmentDescriptor(tag="Debug", type="DEBUG", environment=debug),
                EnvironmentDescriptor(tag="Cached", type="CLEAN", environment=cached),
                EnvironmentDescriptor(tag="Clean", type="CLEAN", environment=base),
                EnvironmentDescriptor(
                    tag="CallTrace", type="CALL_TRACE", environment=call_trace
                ),
                EnvironmentDescriptor(
                    tag="Valgrind", type="VALGRIND", environment=valgrind
                ),
            ],
        )

    def _create_pool_descriptor_for_jvm(
        self,
    ) -> PoolDescriptor:
        base = OssFuzzEnvironment(
            pool=self,
            project_name=self._challenge_project_detection.project_name,
            checkout_ref=self._challenge_project_detection.mode.checkout_ref(),
            max_timeout=self._max_timeout,
        )

        cached = CachedOssFuzzEnvironment(
            pool=self,
            environment=base,
            challenge_project_yaml=self._challenge_project_yaml,
        )

        call_trace = CallTraceOssFuzzEnvironment(
            pool=self,
            environment=base,
            challenge_project_yaml=self._challenge_project_yaml,
            challenge_project_detection=self._challenge_project_detection,
        )

        return PoolDescriptor(
            base=base,
            redirection={
                # To avoid unnecessary environment creation, we redirect the environment type.
                # For example, we do not need a specific debug environment for JVM.
                # Moreover, JVM does not support valgrind, but to be safe, we redirect it to the clean environment.
                "DEBUG": "CLEAN",
                "VALGRIND": "CLEAN",
            },
            descriptors=[
                EnvironmentDescriptor(tag="Cached", type="CLEAN", environment=cached),
                EnvironmentDescriptor(tag="Clean", type="CLEAN", environment=base),
                EnvironmentDescriptor(
                    tag="CallTrace", type="CALL_TRACE", environment=call_trace
                ),
            ],
        )

    def initialize(self, context: EnvironmentContext):
        # By default, we only initialize the clean environment.
        # Other environments are created on demand.

        self.work_directory.mkdir(parents=True, exist_ok=True)
        self.out_directory.mkdir(parents=True, exist_ok=True)
        assert self._create_environment_by_type(context, "CLEAN") is not None

    def _create_environment_by_type(
        self,
        context: EnvironmentContext,
        type: EnvironmentType,
    ) -> tuple[str, EnvironmentProtocol] | None:
        assert type not in self._environments, f"Environment {type} already exists"

        for descriptor in self._pool_descriptor.descriptors:
            if descriptor.type != type:
                continue

            success = self._create_environment(context=context, descriptor=descriptor)
            if success:
                context["logger"].info(
                    f"Successfully created {descriptor.tag} for {descriptor.type} environment"
                )

                self._environments[descriptor.type] = (
                    descriptor.tag,
                    descriptor.environment,
                )

                context["logger"].info(
                    f"Current environments: {[f'{type} -> {tag}' for type, (tag, _) in self._environments.items()]}"
                )
                return (descriptor.tag, descriptor.environment)

        return None

    def _create_environment(
        self,
        context: EnvironmentContext,
        descriptor: EnvironmentDescriptor,
    ) -> bool:
        sanitizer_name = context.get("sanitizer_name")
        env_tag_key = "/".join([descriptor.tag, sanitizer_name])
        env_type_key = "/".join([descriptor.type, sanitizer_name])
        # If the same type of environment already exists, use it
        metadata = Metadata.read(
            self._cache_directory, self._challenge_project_detection
        )

        self._enable_tests = metadata.run_tests_status

        if metadata.measured_times is not None:
            self._pool_descriptor.base.set_timeout(context, *metadata.measured_times)

        if metadata.type_to_tag.get(env_type_key, None):
            return descriptor.tag == metadata.type_to_tag[env_type_key]

        # If we have already tried this environment, use the result
        # TODO: Handle repeated retries more gracefully.
        # Currently, this simply retries the build on failure without distinguishing the error.
        # Related issue fixed in PR #959
        if env_tag_key in metadata.build_status and metadata.build_status[env_tag_key]:
            return metadata.build_status[env_tag_key]

        build_success, run_tests_success, build_elapsed_time, run_tests_elapsed_time = (
            self._build_and_run_tests_environment(descriptor, context)
        )
        metadata.build_status[env_tag_key] = build_success
        metadata.run_tests_status = run_tests_success
        self._enable_tests = run_tests_success
        if not run_tests_success:
            context["logger"].warning(
                f"Failed to run tests for {descriptor.tag}-{descriptor.type} environment. Not running tests for this environment."
            )

        if build_success and descriptor.type == "CLEAN":
            # For the clean environment, we store the build and run tests timeouts.
            metadata.measured_times = (
                build_elapsed_time,
                run_tests_elapsed_time,
            )
            self._pool_descriptor.base.set_timeout(context, *metadata.measured_times)

        if build_success:
            metadata.type_to_tag[env_type_key] = descriptor.tag
            self._store_environment(
                descriptor.environment,
                context,
                self._challenge_project_detection,
                descriptor.tag,
            )

        Metadata.write(
            self._cache_directory, self._challenge_project_detection, metadata
        )
        return build_success

    def _build_and_run_tests_environment(
        self,
        descriptor: EnvironmentDescriptor,
        context: EnvironmentContext,
    ) -> tuple[bool, bool, int, int]:
        with logging_performance(
            context, f"Building {descriptor.tag} for {descriptor.type} environment"
        ):
            start_time = time.time()
            build_success = self._build_environment(descriptor.environment, context)
            build_elapsed_time = time.time() - start_time

        if not build_success:
            return False, False, self._max_timeout, self._max_timeout

        if self._enable_tests:
            with logging_performance(
                context,
                f"Running tests for {descriptor.tag} for {descriptor.type} environment",
            ):
                start_time = time.time()
                run_tests_success = self._run_tests_environment(
                    descriptor.environment, context
                )
                run_tests_elapsed_time = time.time() - start_time
        else:
            run_tests_success = False
            run_tests_elapsed_time = 0

        return (
            build_success,
            run_tests_success,
            int(build_elapsed_time),
            int(run_tests_elapsed_time),
        )

    def _build_environment(
        self,
        environment: EnvironmentProtocol,
        context: EnvironmentContext,
    ) -> bool:
        try:
            environment.restore(context)
            environment.build(context)
            return True
        except ChallengeBuildFailedError as e:
            context["logger"].error("Failed to build environment:")
            context["logger"].debug(f"Stdout: {e.stdout}")
            context["logger"].debug(f"Stderr: {e.stderr}")
            return False
        except Exception as e:
            context["logger"].error(f"Failed to build environment: {e}")
            return False

    def _run_tests_environment(
        self,
        environment: EnvironmentProtocol,
        context: EnvironmentContext,
    ) -> bool:
        try:
            environment.run_tests(context)
            return True
        except Exception as e:
            context["logger"].error(f"Failed to run tests: {e}")
            return False

    def _store_environment(
        self,
        environment: EnvironmentProtocol,
        context: EnvironmentContext,
        challenge_project_detection: AIxCCChallengeProjectDetection,
        tag: str,
    ):
        snaphot_directory = (
            self._cache_directory / challenge_project_detection.project_name / tag
        )
        snaphot_directory.mkdir(parents=True, exist_ok=True)

        save_environment(self, context, snaphot_directory)

    def _get_environment(
        self,
        context: EnvironmentContext,
        type: EnvironmentType,
    ) -> tuple[str, EnvironmentProtocol] | None:
        if type in self._environments:
            return self._environments[type]
        else:
            # If the environment does not exist, create it on demand.
            return self._create_environment_by_type(context, type)

    def use(
        self,
        context: EnvironmentContext,
        type: EnvironmentType,
    ) -> EnvironmentProtocol | None:
        type = self._pool_descriptor.redirection.get(type, type)
        result = self._get_environment(context, type)
        if result is None:
            return None

        tag, environment = result

        load_environment(
            self,
            context,
            self._cache_directory
            / self._challenge_project_detection.project_name
            / tag,
        )
        return environment

    def internal_test_script_path(self) -> Path:
        # Standard AFC test file path from r3 integration-test.
        # See #1213 for details.
        return self.project_directory / "test.sh"

    def internal_test_exists(self) -> bool:
        # Hotfix for CRS-Patch.
        if not self._enable_tests:
            return False

        return self.internal_test_script_path().exists()
