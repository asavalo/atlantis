from pathlib import Path

from python_oss_fuzz.path.globals import OSS_FUZZ_DIRECTORY

from crete.atoms.detection import Detection
from crete.commons.docker.functions import reproduce_extended
from crete.commons.interaction.exceptions import CommandInteractionError
from crete.framework.evaluator.contexts import EvaluatingContext


class JVMTimeoutStacktraceAnalyzer:
    # TODO: cache it
    def analyze(self, context: EvaluatingContext, detection: Detection) -> bytes | None:
        assert detection.language == "jvm", (
            "JVMTimeoutStacktraceAnalyzer is only supported for JVM projects"
        )

        context["pool"].restore(context)

        project_name = detection.project_name
        harness_name = detection.blobs[0].harness_name
        scripts_path = Path(__file__).parent / "scripts"

        try:
            reproduce_extended(
                project_name=project_name,
                harness_name=harness_name,
                blob=detection.blobs[0].blob,
                cmd=["/scripts/reproduce_with_jstack.sh", harness_name],
                extra_docker_args=[
                    "-v",
                    f"{scripts_path}:/scripts",
                ],
            )
        except CommandInteractionError as e:
            context["logger"].error(f"reproduce_extended failed: {e}")
            return None

        jstack_output_path = (
            OSS_FUZZ_DIRECTORY / "build/out" / project_name / "jstack.txt"
        )
        if jstack_output_path.exists():
            context["logger"].info(f"Found jstack output at {jstack_output_path}")
            return jstack_output_path.read_bytes()
        else:
            context["logger"].warning(
                f"jstack output not found at {jstack_output_path}"
            )
            return None
