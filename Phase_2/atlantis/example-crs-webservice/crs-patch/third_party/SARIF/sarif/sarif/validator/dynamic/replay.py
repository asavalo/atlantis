import argparse
import json
import os
from pathlib import Path

from loguru import logger

from sarif.context import SarifEnv
from sarif.models import CP
from sarif.utils.cmd import BaseCommander
from sarif.utils.docker import OSSFuzzDocker
from sarif.validator.dynamic.coverage import (
    FunctionCoverage,
    FuzzerCoverage,
    get_coverage_info_from_jacoco,
    merge_coverage_info,
)

cmd = BaseCommander()


class CoverageOSSFuzz(OSSFuzzDocker):
    tool_name: str = "coverage"
    build_name: str = "coverage-db"
    # Use oss-fuzz image
    dockerfile = ""

    def __init__(
        self,
        cp: CP,
        *,
        oss_fuzz_dir: Path | None = None,
        corpus_dir: Path | None = None,
    ):
        super().__init__(cp)

        self.oss_fuzz_dir = oss_fuzz_dir

        if self.oss_fuzz_dir is None:
            self.oss_fuzz_dir = os.getenv("OSS_FUZZ_DIR")
            if self.oss_fuzz_dir is None:
                raise ValueError("OSS_FUZZ_DIR is not set")

            self.oss_fuzz_dir = Path(self.oss_fuzz_dir)

        self.corpus_dir = corpus_dir

        if self.corpus_dir is None:
            self.corpus_dir = os.getenv("CORPUS_DIR")
            if self.corpus_dir is None:
                raise ValueError("CORPUS_DIR is not set")

            self.corpus_dir = Path(self.corpus_dir)

        if not self.oss_fuzz_dir.exists() or not self.corpus_dir.exists():
            raise ValueError(
                f"OSS_FUZZ_DIR {self.oss_fuzz_dir} or CORPUS_DIR {self.corpus_dir} does not exist"
            )

    def _build_coverage_fuzzer(self):
        # Check whether fuzzer has already built
        all_built = True
        for harness_name in [harness.name for harness in self.cp.harnesses]:
            # TODO: check the sanitizer was set as "coverage"
            fuzzer_path = SarifEnv().out_dir / harness_name
            if not fuzzer_path.exists():
                all_built = False
                break

        if all_built:
            logger.info(f"Coverage fuzzer {self.cp.name} already built. skipping...")
            return

        logger.debug(f"Building coverage fuzzer {self.cp.name}...")

        # Build fuzzer
        ret = cmd.run(
            f"python3 infra/helper.py build_fuzzers --sanitizer=coverage {self.project_full_name}",
            cwd=self.oss_fuzz_dir,
        )

        if ret.returncode != 0:
            logger.error(f"Failed to build coverage fuzzer")
            raise ValueError(f"Failed to build coverage fuzzer")

        logger.debug(f"Coverage fuzzer {self.cp.name} built successfully")

    def _run_coverage_one_harness(self, harness_name: str):
        # python $OSS_FUZZ_DIR/infra/helper.py coverage --fuzz-target=$HARNESS_NAME \
        # --corpus-dir=$CORPUS_DIR/$HARNESS_NAME $PROJECT_NAME

        logger.debug(f"Running coverage for {harness_name}...")

        ret = cmd.run(
            f"python3 infra/helper.py coverage --no-serve --port '' --fuzz-target={harness_name} --corpus-dir={self.corpus_dir}/{harness_name} {self.project_full_name}",
            cwd=self.oss_fuzz_dir,
        )

        if ret.returncode != 0:
            raise ValueError(f"Failed to run coverage for {harness_name}: {ret.stderr}")

        logger.debug(f"Coverage for {harness_name} run successfully")

    def _get_function_coverage_java(self) -> FuzzerCoverage:
        jacoco_path = SarifEnv().out_dir / "textcov_reports" / "jacoco.xml"

        if not jacoco_path.exists():
            raise ValueError(f"Jacoco report not found at {jacoco_path}")

        return get_coverage_info_from_jacoco(jacoco_path)

    def _get_function_coverage_c(self, harness_name: str) -> FuzzerCoverage:
        # e.g.) docker run --privileged --shm-size=2g --platform linux/amd64 --rm -i -e FUZZING_ENGINE=libfuzzer -e HELPER=True -e FUZZING_LANGUAGE=c -e PROJECT=aixcc/c/mock-c -e SANITIZER=coverage -e 'COVERAGE_EXTRA_ARGS= ' -e ARCHITECTURE=x86_64 -v /home/user/work/team-atlanta/c-corpus/harness:/corpus/ossfuzz-1 -v /home/user/work/team-atlanta/oss-fuzz/build/out/aixcc/c/mock-c:/out -t gcr.io/oss-fuzz-base/base-runner bash -c "llvm-profdata show -all-functions --covered /out/dumps/ossfuzz-1.profdata | c++filt"

        ret = cmd.run(
            f"docker run --privileged --shm-size=2g --platform linux/amd64 --rm -i -e FUZZING_ENGINE=libfuzzer -e HELPER=True -e FUZZING_LANGUAGE=c -e PROJECT={self.project_full_name} -e SANITIZER=coverage -e 'COVERAGE_EXTRA_ARGS= ' -e ARCHITECTURE=x86_64 -v {self.corpus_dir}/{harness_name}:/corpus/{harness_name} -v {self.out_dir}:/out gcr.io/oss-fuzz-base/base-runner bash -c 'llvm-profdata show -all-functions --covered /out/dumps/{harness_name}.profdata | c++filt'",
            cwd=self.oss_fuzz_dir,
            pipe=True,
        )

        if ret.returncode != 0:
            raise ValueError(
                f"Failed to get function coverage for {harness_name}: {ret.stderr}"
            )

        function_list_str = ret.stdout
        function_list = function_list_str.split("\n")

        fuzzer_coverage = FuzzerCoverage(func_coverages=[])

        for function_name in function_list:
            if function_name.strip() == "":
                continue

            # TODO: get class name and file name
            fuzzer_coverage.func_coverages.append(
                FunctionCoverage(
                    class_name="",
                    file_name="",
                    func_name=function_name,
                    desc="",
                )
            )

        return fuzzer_coverage

    def get_function_coverage(self) -> FuzzerCoverage:
        self._build_coverage_fuzzer()

        coverage_infos: list[FuzzerCoverage] = []

        for harness_name in [harness.name for harness in self.cp.harnesses]:
            try:
                self._run_coverage_one_harness(harness_name)

                fuzzer_coverage = (
                    self._get_function_coverage_java()
                    if self.cp.language == "java"
                    else self._get_function_coverage_c(harness_name)
                )
            except Exception as e:
                logger.error(f"Failed to get function coverage for {harness_name}: {e}")
                continue

            coverage_infos.append(fuzzer_coverage)

        return merge_coverage_info(coverage_infos)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-name", type=str, required=True)
    parser.add_argument("--harness-names", type=str, required=True)
    parser.add_argument("--language", type=str, required=True)
    parser.add_argument("--oss-fuzz-dir", type=str, required=False)
    parser.add_argument("--corpus-dir", type=str, required=False)
    args = parser.parse_args()

    oss_fuzz_dir = Path(args.oss_fuzz_dir) if args.oss_fuzz_dir else None
    corpus_dir = Path(args.corpus_dir) if args.corpus_dir else None

    coverage = CoverageOSSFuzz(
        project_name=args.project_name,
        harness_names=args.harness_names.split(","),
        language=args.language,
        oss_fuzz_dir=oss_fuzz_dir,
        corpus_dir=corpus_dir,
    )

    func_coverage = coverage.get_function_coverage()

    with open("function_coverage.json", "w") as f:
        json.dump([c.model_dump() for c in func_coverage], f)
