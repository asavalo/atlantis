import atexit
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from crete.atoms.action import HeadAction
from crete.atoms.report import CreteResult, DiffResult, ErrorResult, result_from_action
from crete.framework.context_builder.services.aixcc import AIxCCContextBuilder
from crs_patch.exceptions.patch_checker import (
    BuildError,
    FunctionalTestError,
    GitApplyError,
    PoVError,
    SourceDirectoryInitError,
)
from crs_patch.models.models import BlobInfo, PatchRequest, TaskType
from crs_patch.services.patch_checker import PatchChecker
from python_aixcc_challenge.detection.models import (
    AIxCCChallengeDeltaMode,
    AIxCCChallengeProjectDetection,
)
from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY


def _initialize_patch_checker_from_source(
    detection: AIxCCChallengeProjectDetection, source_directory: Path
) -> PatchChecker:
    patch_checker = PatchChecker()

    temp_dir = Path(tempfile.mkdtemp())
    patch_checker.temp_dir = temp_dir
    atexit.register(lambda: shutil.rmtree(temp_dir.as_posix()))
    patch_checker.source_directory = source_directory
    patch_checker.local_oss_fuzz_directory = OSS_FUZZ_DIRECTORY
    patch_checker.ossfuzz_helper_script = OSS_FUZZ_DIRECTORY / "infra" / "helper.py"

    subprocess.check_call(
        f"git -C {source_directory} checkout {detection.mode.checkout_ref()}",
        shell=True,
    )
    patch_checker.restore()
    return patch_checker


def _detection_to_patch_request(
    detection: AIxCCChallengeProjectDetection,
) -> PatchRequest:
    task_type = (
        TaskType.delta
        if isinstance(detection.mode, AIxCCChallengeDeltaMode)
        else TaskType.full
    )
    return PatchRequest(
        project_name=detection.project_name,
        blobs=[
            BlobInfo(
                harness_name=blob.harness_name,
                sanitizer_name=blob.sanitizer_name,
                blob_data=blob.blob,
            )
            for blob in detection.blobs
        ],
        pov_id=uuid.uuid4(),
        sarif_report=detection.sarif_report,
        type=task_type,
    )


def verify_patch_with_patch_checker(
    detection_file: Path,
    source_directory: Path,
    patch_file: Path,
) -> CreteResult:
    detection = AIxCCChallengeProjectDetection.from_toml(detection_file)
    patch_checker = _initialize_patch_checker_from_source(detection, source_directory)
    try:
        patch_checker.check(
            patch_file.read_text(), _detection_to_patch_request(detection)
        )
    except SourceDirectoryInitError as e:
        return ErrorResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="unknown_error",
            error=str(e),
        )
    except GitApplyError:
        return DiffResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="wrong",
            diff=patch_file.read_text(),
            stdout=b"",
            stderr=b"",
        )
    except BuildError:
        return DiffResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="uncompilable",
            diff=patch_file.read_text(),
            stdout=b"",
            stderr=b"",
        )
    except PoVError:
        return DiffResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="vulnerable",
            diff=patch_file.read_text(),
            stdout=b"",
            stderr=b"",
        )
    except FunctionalTestError:
        return DiffResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="compilable",
            diff=patch_file.read_text(),
            stdout=b"",
            stderr=b"",
        )
    except Exception as e:
        return ErrorResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="unknown_error",
            error=str(e),
        )
    else:
        return DiffResult(
            project_name=detection.project_name,
            vulnerability_identifier=detection.vulnerability_identifier,
            source_directory=source_directory,
            variant="sound",
            diff=patch_file.read_text(),
            stdout=b"",
            stderr=b"",
        )


def verify_patch_with_crete(
    detection_file: Path,
    source_directory: Path,
    patch_file: Path,
) -> CreteResult:
    context_builder = AIxCCContextBuilder(
        challenge_project_directory=source_directory,
        detection_toml_file=detection_file,
    )
    context, detection = context_builder.build(
        previous_action=HeadAction(),
    )
    context["pool"].use(context, "CLEAN")
    result = context["evaluator"].evaluate(context, patch_file.read_bytes(), detection)
    context["pool"].restore(context)
    return result_from_action(context_builder, result)
