#!/usr/bin/env python3
"""
Standalone ZIP file generator for CRS-multilang experiment data.
This script generates ZIP files for individual experiments and aggregate collections.
Optimized version using Unix commands and parallel processing.
"""

import argparse
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

from loguru import logger

from experiments import discover_available_dates, discover_experiments, format_file_size

# Configure logger to INFO level
logger.remove()
logger.add(sys.stderr, level="INFO")


# Constants
EXPERIMENT_ZIP_TYPES = ["povs", "workdir", "eval"]
AGGREGATE_ZIP_TYPES = ["povs", "workdirs", "evals", "stdout"]

ZIP_TYPE_PATHS = {
    "povs": ("eval_result", "povs"),
    "workdir": ("workdir_result",),
    "eval": ("eval_result",),
}

AGGREGATE_ZIP_PATHS = {
    "povs": ("eval_result", "povs"),
    "workdirs": ("workdir_result",),
    "evals": ("eval_result",),
    "stdout": None,  # Special case handled separately
}


class ZipGenerator:
    """Optimized ZIP file generator using Unix commands and parallel processing"""

    def __init__(self, eval_dir: Path, max_workers: int = 4):
        eval_dir = eval_dir.resolve()
        self.eval_dir = eval_dir
        self.zipfiles_dir = eval_dir / "zipfiles"
        self.max_workers = max_workers

        # Ensure zipfiles directory exists
        self.zipfiles_dir.mkdir(exist_ok=True)

    def get_zip_path(
        self, config_hash: str, target: str, harness: str, zip_type: str
    ) -> Path:
        """Get the path where a ZIP file should be located"""
        # Replace "/" with "-" to make valid filename
        safe_target = target.replace("/", "-")
        filename = f"{config_hash}_{safe_target}_{harness}_{zip_type}.zip"
        zip_path = self.zipfiles_dir / filename
        zip_path = zip_path.resolve()

        # Debug logging when ZIP file exists
        if zip_path.exists():
            logger.debug(f"Found ZIP file: {zip_path}")

        return zip_path

    def get_aggregate_zip_path(self, zip_type: str) -> Path:
        """Get the path for aggregate ZIP files"""
        return self.zipfiles_dir / f"all-{zip_type}.zip"

    def check_zip_availability(
        self, config_hash: str, target: str, harness: str
    ) -> dict:
        """Check which ZIP files are available for an experiment with file sizes"""
        return self._check_zip_availability_helper(
            EXPERIMENT_ZIP_TYPES,
            lambda zip_type: self.get_zip_path(config_hash, target, harness, zip_type),
        )

    def check_aggregate_zip_availability(self) -> dict:
        """Check which aggregate ZIP files are available with file sizes"""
        return self._check_zip_availability_helper(
            AGGREGATE_ZIP_TYPES, self.get_aggregate_zip_path
        )

    def _check_zip_availability_helper(self, zip_types: List[str], path_func) -> dict:
        """Helper method to check ZIP availability"""
        available = {}
        for zip_type in zip_types:
            zip_path = path_func(zip_type)
            if zip_path.exists():
                file_size = zip_path.stat().st_size
                available[zip_type] = {
                    "available": True,
                    "size_display": format_file_size(file_size),
                }
            else:
                available[zip_type] = {"available": False}
        return available

    def generate_experiment_zips(
        self, config_hash: str, target: str, harness: str
    ) -> bool:
        """Generate all ZIP files for a specific experiment"""
        logger.info(
            f"Generating ZIP files for experiment: {config_hash}/{target}/{harness}"
        )

        # Find the experiment base path
        base_path = self.eval_dir / "results" / config_hash / target
        if not base_path.exists():
            logger.error(f"Experiment path not found: {base_path}")
            return False

        success = True

        # Generate individual ZIP files
        for zip_type in EXPERIMENT_ZIP_TYPES:
            try:
                zip_path = self.get_zip_path(config_hash, target, harness, zip_type)
                success &= self._create_experiment_zip(base_path, zip_path, zip_type)
            except Exception as e:
                logger.error(
                    f"Failed to generate {zip_type} ZIP for"
                    f" {config_hash}/{target}/{harness}: {e}"
                )
                success = False

        return success

    def generate_aggregate_zips(self, multilang_root: Path = None) -> bool:
        """Generate all aggregate ZIP files using parallel processing"""
        logger.info("Generating aggregate ZIP files...")

        # Discover all experiments using config-based discovery
        experiment_reports = discover_experiments(self.eval_dir, multilang_root)
        if not experiment_reports:
            logger.warning("No experiments found for aggregate ZIP generation")
            return False

        # Convert ExperimentReport objects to dict format for compatibility
        experiments = []
        for report in experiment_reports:
            experiments.append(
                {
                    "config_hash": report.config_hash,
                    "target": report.target,
                    "harness": report.harness_name,
                    "base_path": report.base_path,
                }
            )

        logger.info(f"Found {len(experiments)} experiments for aggregation")

        # Generate aggregate ZIPs in parallel
        success = True

        with ThreadPoolExecutor(
            max_workers=min(len(AGGREGATE_ZIP_TYPES), self.max_workers)
        ) as executor:
            future_to_type = {
                executor.submit(
                    self._create_aggregate_zip_parallel, zip_type, experiments
                ): zip_type
                for zip_type in AGGREGATE_ZIP_TYPES
            }

            for future in as_completed(future_to_type):
                zip_type = future_to_type[future]
                try:
                    result = future.result()
                    if result:
                        logger.success(
                            "Generated aggregate ZIP:"
                            f" {self.get_aggregate_zip_path(zip_type)}"
                        )
                    else:
                        success = False
                except Exception as e:
                    import traceback

                    traceback.print_exc()
                    logger.error(f"Failed to generate aggregate {zip_type} ZIP: {e}")
                    success = False

        return success

    def has_any_file(self, dir_path: Path) -> bool:
        """Efficiently checks if there's at least one file using find command"""
        if not dir_path.exists():
            return False

        try:
            result = subprocess.run(
                ["find", str(dir_path), "-type", "f", "-print", "-quit"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and result.stdout.strip() != ""
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            # Fallback to Python implementation
            for p in dir_path.rglob("*"):
                if p.is_file():
                    return True
            return False

    def _run_zip_command(
        self, zip_path: Path, source_dir: Path, parent_dir: Optional[Path] = None
    ) -> bool:
        """Run zip command for single directory with proper error handling"""
        try:
            # Remove existing ZIP file if it exists
            if zip_path.exists():
                zip_path.unlink()

            if not parent_dir:
                parent_dir = self.eval_dir.parent

            relative_source_dir = source_dir.relative_to(parent_dir)
            cmd = ["zip", "-rq", str(zip_path), str(relative_source_dir)]

            result = subprocess.run(
                cmd,
                cwd=parent_dir,
                # capture_output=True,
                # text=True,
                # timeout=300  # 5 minute timeout
            )

            if result.returncode != 0:
                logger.error(f"ZIP command failed: {result.stderr}")
                print(result)
                return False

            return True

        except subprocess.TimeoutExpired:
            logger.error(f"ZIP command timed out for {zip_path}")
            return False
        except Exception as e:
            logger.error(f"ZIP command error: {e}")
            return False

    def _run_zip_command_multiple(
        self, zip_path: Path, source_dirs: List[Path], parent_dir: Optional[Path] = None
    ) -> bool:
        """Run zip command for multiple directories using file list approach"""
        try:
            # Remove existing ZIP file if it exists
            if zip_path.exists():
                zip_path.unlink()

            if not parent_dir:
                parent_dir = self.eval_dir.parent

            relative_dirs = [
                d.relative_to(parent_dir) for d in source_dirs if d.exists()
            ]
            if not relative_dirs:
                logger.warning("No valid source directories found")
                return True

            # Use file list approach for multiple directories
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                for rel_dir in relative_dirs:
                    f.write(f"{rel_dir}\n")
                temp_file_path = f.name

            try:
                cmd = ["zip", "-rq", str(zip_path), "-@"]
                with open(temp_file_path, "r") as f:
                    result = subprocess.run(
                        cmd,
                        stdin=f,
                        cwd=parent_dir,
                        # capture_output=True,
                        # text=True,
                        # timeout=1000  # 5 minute timeout
                    )

                if result.returncode != 0:
                    logger.error(f"ZIP command failed: {result.stderr}")
                    return False

                return True

            finally:
                Path(temp_file_path).unlink(missing_ok=True)

        except subprocess.TimeoutExpired:
            logger.error(f"ZIP command timed out for {zip_path}")
            return False
        except Exception as e:
            logger.error(f"ZIP command error: {e}")
            return False

    def _create_experiment_zip(
        self, base_path: Path, zip_path: Path, zip_type: str
    ) -> bool:
        """Create ZIP file for experiment using Unix commands"""
        if zip_type not in ZIP_TYPE_PATHS:
            logger.error(f"Unknown zip type: {zip_type}")
            return False

        # Build the source directory path
        path_parts = ZIP_TYPE_PATHS[zip_type]
        source_dir = base_path
        for part in path_parts:
            source_dir = source_dir / part

        if not source_dir.exists():
            logger.warning(f"{zip_type} directory not found: {source_dir}")
            return True

        if not self.has_any_file(source_dir):
            logger.info(
                f"No {zip_type} files found, skipping ZIP creation: {source_dir}"
            )
            return True

        success = self._run_zip_command(zip_path, source_dir=source_dir)
        if success:
            logger.success(f"Generated ZIP: {zip_path}")
        return success

    def _create_aggregate_zip_parallel(
        self, zip_type: str, experiments: List[dict]
    ) -> bool:
        """Create aggregate ZIP file using collected directory paths"""
        zip_path = self.get_aggregate_zip_path(zip_type)

        exp_dirs = []
        for exp in experiments:
            base_path = exp["base_path"]
            target = exp["target"]
            config_hash = exp["config_hash"]

            target_dir = None

            if zip_type == "povs":
                target_dir = base_path / "eval_result" / "povs"
            elif zip_type == "workdirs":
                target_dir = base_path / "workdir_result"
            elif zip_type == "evals":
                target_dir = base_path / "eval_result"
            elif zip_type == "stdout":
                target_dir = self.eval_dir / "stdout" / target / f"{config_hash}.txt"

            if target_dir and self.has_any_file(target_dir):
                exp_dirs.append(target_dir)

        if not exp_dirs:
            logger.info(f"No aggregate files found, skipping ZIP creation: {zip_path}")
            return True

        success = self._run_zip_command_multiple(zip_path, source_dirs=exp_dirs)
        if success:
            logger.success(f"Generated ZIP: {zip_path}")

        return success

    def _copy_povs_to_temp(self, base_path: Path, temp_dir: Path) -> bool:
        """Copy PoV files to temporary directory"""
        povs_dir = base_path / "eval_result" / "povs"
        if not povs_dir.exists() or not self.has_any_file(povs_dir):
            return False

        dest_dir = temp_dir / "povs"
        dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.run(
                ["cp", "-r", f"{povs_dir}/.", str(dest_dir)],
                check=True,
                # capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _copy_workdir_to_temp(self, base_path: Path, temp_dir: Path) -> bool:
        """Copy workdir_result to temporary directory"""
        workdir_result = base_path / "workdir_result"
        if not workdir_result.exists() or not self.has_any_file(workdir_result):
            return False

        dest_dir = temp_dir / "workdir_result"
        dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.run(
                ["cp", "-r", f"{workdir_result}/.", str(dest_dir)],
                check=True,
                # capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _copy_eval_to_temp(self, base_path: Path, temp_dir: Path) -> bool:
        """Copy eval_result to temporary directory"""
        eval_result = base_path / "eval_result"
        if not eval_result.exists() or not self.has_any_file(eval_result):
            return False

        dest_dir = temp_dir / "eval_result"
        dest_dir.mkdir(parents=True, exist_ok=True)

        try:
            subprocess.run(
                ["cp", "-r", f"{eval_result}/.", str(dest_dir)],
                check=True,
                # capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _copy_stdout_to_temp(
        self, config_hash: str, target: str, temp_dir: Path
    ) -> bool:
        """Copy stdout file to temporary directory"""
        stdout_file = self.eval_dir / "stdout" / target / f"{config_hash}.txt"
        if not stdout_file.exists():
            return False

        temp_dir.mkdir(parents=True, exist_ok=True)
        dest_file = temp_dir / "stdout.txt"

        try:
            subprocess.run(
                ["cp", str(stdout_file), str(dest_file)],
                check=True,
                # capture_output=True
            )
            return True
        except subprocess.CalledProcessError:
            return False


def generate_experiment_zips(
    eval_dir: Path, config_hash: str, target: str, harness: str
) -> bool:
    """Generate all ZIP files for a specific experiment"""
    generator = ZipGenerator(eval_dir)
    return generator.generate_experiment_zips(config_hash, target, harness)


def generate_aggregate_zips(eval_dir: Path, multilang_root: Path = None) -> bool:
    """Generate all aggregate ZIP files"""
    generator = ZipGenerator(eval_dir)
    return generator.generate_aggregate_zips(multilang_root)


def _generate_all_zips(
    generator: ZipGenerator,
    eval_dir: Path,
    max_workers: int,
    multilang_root: Path = None,
) -> bool:
    """Helper function to generate all ZIP files"""
    experiment_reports = discover_experiments(eval_dir, multilang_root)
    success = True

    # Generate individual experiment ZIPs in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for report in experiment_reports:
            future = executor.submit(
                generator.generate_experiment_zips,
                report.config_hash,
                report.target,
                report.harness_name,
            )
            futures.append(future)

        for future in as_completed(futures):
            try:
                result = future.result()
                success = success and result
            except Exception as e:
                logger.error(f"Experiment ZIP generation failed: {e}")
                success = False

    # Generate aggregate ZIPs
    agg_success = generator.generate_aggregate_zips(multilang_root)
    return success and agg_success


def main():
    """CLI interface for manual ZIP generation"""
    parser = argparse.ArgumentParser(
        description="Generate ZIP files for CRS-multilang experiment data"
    )
    parser.add_argument(
        "--root-eval-dir",
        type=Path,
        default="./eval_out_root",
        help=(
            "Root directory containing multiple evaluation subdirectories (default:"
            " ./eval_out_root)"
        ),
    )
    parser.add_argument(
        "--eval-dir",
        type=Path,
        help=(
            "Specific evaluation directory to process (if not provided, uses latest"
            " from --root-eval-dir)"
        ),
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Maximum number of parallel workers (default: 4)",
    )
    parser.add_argument(
        "--multilang-root",
        type=Path,
        help="Path to CRS-multilang root directory (for target info loading)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help=(
            "Process all evaluation directories in --root-eval-dir (instead of just"
            " latest)"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Experiment-specific ZIP generation
    exp_parser = subparsers.add_parser(
        "experiment", help="Generate ZIPs for a specific experiment"
    )
    exp_parser.add_argument("config_hash", help="Configuration hash")
    exp_parser.add_argument("target", help="Target name (e.g., aixcc/c/libxml2)")
    exp_parser.add_argument("harness", help="Harness name")

    # Aggregate ZIP generation
    subparsers.add_parser("aggregate", help="Generate aggregate ZIP files")

    # Generate all ZIPs
    subparsers.add_parser("all", help="Generate all ZIP files")

    args = parser.parse_args()

    # Determine eval_dir(s) based on provided arguments
    if args.eval_dir:
        # Use specific eval directory
        eval_dirs = [args.eval_dir]
        if not args.eval_dir.exists():
            logger.error(f"Evaluation directory does not exist: {args.eval_dir}")
            return 1
        logger.info(f"Using specific eval directory: {args.eval_dir}")
    elif args.all:
        # Process all evaluation directories
        if not args.root_eval_dir.exists():
            logger.error(
                f"Root evaluation directory does not exist: {args.root_eval_dir}"
            )
            return 1

        # Discover all available subdirectories
        available_dates = discover_available_dates(args.root_eval_dir)
        if not available_dates:
            logger.error("No valid evaluation subdirectories found!")
            logger.info(
                f"Expected subdirectories with configs/ in: {args.root_eval_dir}"
            )
            return 1

        eval_dirs = [args.root_eval_dir / subdir for subdir in available_dates]
        logger.info(
            f"Processing all {len(eval_dirs)} evaluation directories: {available_dates}"
        )
    else:
        # Use root-eval-dir with latest subdirectory (default behavior)
        if not args.root_eval_dir.exists():
            logger.error(
                f"Root evaluation directory does not exist: {args.root_eval_dir}"
            )
            return 1

        # Discover available subdirectories
        available_dates = discover_available_dates(args.root_eval_dir)
        if not available_dates:
            logger.error("No valid evaluation subdirectories found!")
            logger.info(
                f"Expected subdirectories with configs/ in: {args.root_eval_dir}"
            )
            return 1

        # Use latest subdirectory
        latest_subdir = available_dates[
            0
        ]  # discover_available_dates returns sorted by newest first
        eval_dirs = [args.root_eval_dir / latest_subdir]
        logger.info(
            f"Using latest eval directory: {eval_dirs[0]} (from {latest_subdir})"
        )

    # Process evaluation directories (in parallel if multiple)
    overall_success = True

    if len(eval_dirs) == 1:
        # Single directory - process normally
        eval_dir = eval_dirs[0]
        logger.info(f"Processing evaluation directory: {eval_dir}")
        generator = ZipGenerator(eval_dir, max_workers=args.max_workers)

        if args.command == "experiment":
            logger.info(
                "Generating experiment ZIPs for"
                f" {args.config_hash}/{args.target}/{args.harness}"
            )
            success = generator.generate_experiment_zips(
                args.config_hash, args.target, args.harness
            )

        elif args.command == "aggregate":
            logger.info("Generating aggregate ZIP files")
            success = generator.generate_aggregate_zips(args.multilang_root)

        elif args.command == "all" or args.command is None:
            if args.command is None:
                logger.info("No command specified, defaulting to 'all'")
            logger.info("Generating all ZIP files")
            success = _generate_all_zips(
                generator, eval_dir, args.max_workers, args.multilang_root
            )

        else:
            parser.print_help()
            return 1

        overall_success = success

        if success:
            logger.success(f"ZIP generation completed successfully for: {eval_dir}")
        else:
            logger.error(f"ZIP generation completed with errors for: {eval_dir}")

    else:
        # Multiple directories - process in parallel
        logger.info(
            f"Processing {len(eval_dirs)} evaluation directories in parallel..."
        )

        def process_single_eval_dir(eval_dir):
            """Process a single evaluation directory"""
            try:
                logger.info(f"Processing evaluation directory: {eval_dir}")
                # Use fewer workers per directory when processing multiple directories
                workers_per_dir = max(1, args.max_workers // len(eval_dirs))
                generator = ZipGenerator(eval_dir, max_workers=workers_per_dir)

                if args.command == "experiment":
                    success = generator.generate_experiment_zips(
                        args.config_hash, args.target, args.harness
                    )

                elif args.command == "aggregate":
                    success = generator.generate_aggregate_zips(args.multilang_root)

                elif args.command == "all" or args.command is None:
                    success = _generate_all_zips(
                        generator, eval_dir, workers_per_dir, args.multilang_root
                    )

                else:
                    return False

                if success:
                    logger.success(
                        f"ZIP generation completed successfully for: {eval_dir}"
                    )
                else:
                    logger.error(
                        f"ZIP generation completed with errors for: {eval_dir}"
                    )

                return success

            except Exception as e:
                logger.error(f"Failed to process {eval_dir}: {e}")
                return False

        # Process directories in parallel
        with ThreadPoolExecutor(
            max_workers=min(len(eval_dirs), args.max_workers)
        ) as executor:
            futures = [
                executor.submit(process_single_eval_dir, eval_dir)
                for eval_dir in eval_dirs
            ]

            for future in as_completed(futures):
                try:
                    success = future.result()
                    overall_success = overall_success and success
                except Exception as e:
                    logger.error(f"Directory processing failed: {e}")
                    overall_success = False

    if overall_success:
        logger.success("All ZIP generation completed successfully")
        return 0
    else:
        logger.error("Some ZIP generation completed with errors")
        return 1


if __name__ == "__main__":
    exit(main())
