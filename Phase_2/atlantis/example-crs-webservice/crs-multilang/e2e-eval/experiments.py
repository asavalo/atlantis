#!/usr/bin/env python3
"""
Experiment discovery and management for CRS-multilang evaluation data.
This module provides unified experiment discovery logic used by both run_server.py and generate_zips.py.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from loguru import logger


@dataclass
class TargetCPV:
    name: str
    harness_name: str
    sanitizer: str
    error_token: str
    pov_file_path: Path
    crash_log_path: Path
    crash_log_content: str
    dedup_token: Optional[str] = None


@dataclass
class HarnessInfo:
    name: str
    path: str  # Raw path from config.yaml (with $PROJECT/$REPO)
    resolved_url: str  # Web URL to the harness file


@dataclass
class TargetInfo:
    target: str  # "aixcc/c/mock-c"
    language: str
    project_name: str
    repo_url: str
    repo_url_web: str  # Web-friendly version of repo_url
    harnesses: List[str]
    harness_info: List[HarnessInfo]  # Detailed harness information
    cpvs: List[TargetCPV]
    base_commit: str = "main"  # Base commit from config.yaml


@dataclass
class FoundPoV:
    pov_id: str  # "e9e9c8a7820b7069"
    status: str  # "pending"
    finder: str  # "UniAFL.given_fuzzer"
    harness: str  # "xml"
    sanitizer_output: str  # Crash signature
    time_seconds: int  # Discovery time
    uuid: str  # UUID if available
    matched_cpv: Optional[str] = None  # Which CPV it matches


@dataclass
class ExperimentStats:
    expected_cpvs: int  # From config.yaml
    found_povs: int  # From crash.json
    matched_povs: int  # Found PoVs matching expected CPVs
    unintended_povs: int  # Found PoVs with no expected match
    missing_cpvs: int  # Expected CPVs not found
    found_pov_details: List[FoundPoV]  # Full details for analysis


@dataclass
class GitSubmodule:
    path: str
    commit: str
    date_utc: str


@dataclass
class GitInfo:
    main_commit: str
    main_commit_date: str
    submodules: List[GitSubmodule]
    dirty: bool
    dirty_files: Optional[str] = None


@dataclass
class LiteLLMStats:
    total_spend: float = 0.0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_tokens: int = 0
    total_api_requests: int = 0
    total_successful_requests: int = 0
    total_failed_requests: int = 0
    total_cache_read_input_tokens: int = 0
    total_cache_creation_input_tokens: int = 0


@dataclass
class SeedInfo:
    hash: str
    finder: str
    corpus_type: str  # "pov", "others_corpus", "uniafl_corpus"
    file_path: Path
    metadata_path: Path


@dataclass
class FinderStats:
    finder_name: str
    pov_count: int
    matched_pov_count: int  # PoVs that matched expected CPVs
    unintended_pov_count: int  # PoVs that were unintended
    others_corpus_count: int
    uniafl_corpus_count: int
    total_seeds: int


@dataclass
class CorpusAnalysis:
    seeds: List[SeedInfo]
    finder_stats: List[FinderStats]
    total_povs: int
    total_others_corpus: int
    total_uniafl_corpus: int
    unique_finders: set[str]


@dataclass
class ExperimentReport:
    experiment_name: str
    target: str
    harness_name: str
    config_hash: str
    input_gens: List[str]
    base_path: Path
    reports_path: Path
    zip_files: Dict[str, bool] = None  # Track which ZIP files are available
    experiment_duration: Optional[str] = None  # Human-readable duration
    experiment_start_time: Optional[str] = None  # Human-readable start time
    experiment_end_time: Optional[str] = None  # Human-readable end time
    target_info: Optional[TargetInfo] = None
    experiment_stats: Optional[ExperimentStats] = None
    litellm_stats: Optional[LiteLLMStats] = None
    is_complete: bool = True  # New field to track completion status
    has_stdout: bool = True  # New field to track if stdout exists
    git_info: Optional[GitInfo] = None  # Git repository information
    corpus_analysis: Optional[CorpusAnalysis] = None  # Corpus analysis data


def fetch_config_files(eval_dir: Path) -> Dict[str, Dict]:
    """Step 1: Fetch all config files and their metadata"""
    configs = {}

    configs_dir = eval_dir / "configs"
    if not configs_dir.exists():
        logger.warning(f"Configs directory not found: {configs_dir}")
        return configs

    logger.info("Step 1: Fetching config files...")

    # Recursively find all JSON files in the configs directory
    for config_file in configs_dir.rglob("*.json"):
        # Get the target path relative to configs directory
        target = str(config_file.parent.relative_to(configs_dir))
        config_hash = config_file.stem

        try:
            with open(config_file, "r") as f:
                config_data = json.load(f)

            configs[f"{target}#{config_hash}"] = {
                "target": target,
                "config_hash": config_hash,
                "harnesses": config_data.get("target_harnesses", []),
                "input_gens": config_data.get("others", {}).get("input_gens", []),
                "config_file": config_file,
            }

            logger.debug(f"Loaded config: {target} (hash: {config_hash})")

        except Exception as e:
            logger.warning(f"Failed to load config {config_file}: {e}")

    logger.info(f"Found {len(configs)} config combinations")
    return configs


def calculate_experiment_duration(
    eval_dir: Path, target: str, config_hash: str, harness_name: str = None
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Calculate experiment duration from stdout logs with precise start/end times

    Returns:
        tuple: (duration_str, start_time_str, end_time_str) where all can be None if not available
    """
    stdout_file = eval_dir / "stdout" / target / f"{config_hash}.txt"

    if not stdout_file.exists():
        logger.debug(f"Stdout file not found: {stdout_file}")
        return None, None, None

    try:
        # Parse start and end times from logs
        start_time = _parse_start_time_from_logs(stdout_file)
        end_time = _parse_end_time_from_logs(stdout_file, harness_name)

        # If log parsing succeeded, use those times
        if start_time and end_time:
            duration_seconds = int(end_time - start_time)
            logger.debug(f"Using log timestamps: start={start_time}, end={end_time}")
        else:
            # Fallback to file timestamps
            duration_seconds = _calculate_duration_from_file_times(stdout_file)
            if duration_seconds is None:
                return None, None, None

        logger.debug(f"File: {stdout_file}")
        logger.debug(f"Duration: {duration_seconds}s")

        # Handle edge cases
        if duration_seconds < 0:
            logger.debug(
                f"Negative duration for {target}/{config_hash}, using absolute value"
            )
            duration_seconds = abs(duration_seconds)

        if duration_seconds == 0:
            return "< 1s", None, None

        # Format duration, start time, and end time as human-readable
        duration_str = _format_duration(duration_seconds)
        start_time_str = _format_start_time(start_time) if start_time else None
        end_time_str = _format_start_time(end_time) if end_time else None
        return duration_str, start_time_str, end_time_str

    except Exception as e:
        logger.warning(f"Failed to calculate duration for {target}/{config_hash}: {e}")
        return None, None, None


def _parse_start_time_from_logs(stdout_file: Path) -> Optional[float]:
    """Parse start time from 'Starting CRS' log entry"""
    try:
        with open(stdout_file, "r", encoding="utf-8", errors="replace") as f:
            # Read first 5 lines to find "Starting CRS"
            for _ in range(5):
                line = f.readline()
                if not line:
                    break

                if "Starting CRS" in line:
                    # Strip ANSI colors and extract timestamp
                    clean_line = _strip_ansi_colors(line)
                    parts = clean_line.split()
                    if len(parts) >= 2:
                        timestamp_str = parts[0] + " " + parts[1]
                        return _parse_timestamp(timestamp_str)

    except Exception as e:
        logger.debug(f"Failed to parse start time from {stdout_file}: {e}")

    return None


def _parse_end_time_from_logs(
    stdout_file: Path, harness_name: str = None
) -> Optional[float]:
    """Parse end time from 'Save result of {harness_name}' log entry"""
    if not harness_name:
        return None

    try:
        with open(stdout_file, "r", encoding="utf-8", errors="replace") as f:
            # Search for "Save result of {harness_name}" pattern
            search_pattern = f"Save result of {harness_name}"

            for line in f:
                if search_pattern in line:
                    # Strip ANSI colors and extract timestamp
                    clean_line = _strip_ansi_colors(line)
                    parts = clean_line.split()
                    if len(parts) >= 2:
                        timestamp_str = parts[0] + " " + parts[1]
                        return _parse_timestamp(timestamp_str)

    except Exception as e:
        logger.debug(f"Failed to parse end time from {stdout_file}: {e}")

    return None


def _strip_ansi_colors(text: str) -> str:
    """Remove ANSI color codes from text"""
    import re

    # ANSI escape sequence pattern
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def _parse_timestamp(timestamp_str: str) -> Optional[float]:
    """Parse timestamp string to Unix timestamp"""
    try:
        from datetime import datetime

        # Parse format: "2025-06-06 15:02:04"
        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except Exception as e:
        logger.debug(f"Failed to parse timestamp '{timestamp_str}': {e}")
        return None


def _calculate_duration_from_file_times(stdout_file: Path) -> Optional[int]:
    """Fallback: Calculate duration using file birth time and modification time"""
    try:
        # Use stat command to get birth time
        result = subprocess.run(
            ["stat", "-c", "%W %Y", str(stdout_file)],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode == 0:
            birth_time_str, mtime_str = result.stdout.strip().split()
            birth_time = float(birth_time_str)
            mtime = float(mtime_str)

            # Birth time of 0 means not available
            if birth_time > 0:
                duration_seconds = int(mtime - birth_time)
                logger.debug(
                    f"Using file timestamps: birth={birth_time}, mtime={mtime}"
                )
                return duration_seconds

    except Exception as e:
        logger.debug(f"stat command failed: {e}")

    logger.warning(f"Could not get file times for {stdout_file}, timing unavailable")
    return None


def _format_duration(duration_seconds: int) -> str:
    """Format duration as human-readable string"""
    hours = duration_seconds // 3600
    minutes = (duration_seconds % 3600) // 60
    seconds = duration_seconds % 60

    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def _format_start_time(start_timestamp: float) -> str:
    """Format start timestamp as human-readable string"""
    from datetime import datetime

    dt = datetime.fromtimestamp(start_timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def aggregate_by_hash(configs: Dict[str, Dict]) -> Dict[str, List[Dict]]:
    """Step 2: Aggregate configs by hash (input generation combinations)"""
    logger.info("Step 2: Aggregating by input generation combinations...")

    hash_groups = {}

    for config_key, config_data in configs.items():
        config_hash = config_data["config_hash"]
        input_gens_str = ", ".join(config_data["input_gens"])

        if config_hash not in hash_groups:
            hash_groups[config_hash] = {
                "input_gens": config_data["input_gens"],
                "input_gens_str": input_gens_str,
                "configs": [],
            }

        hash_groups[config_hash]["configs"].append(config_data)

    logger.info(f"Found {len(hash_groups)} unique input generation combinations")
    for hash_val, group in hash_groups.items():
        logger.debug(
            f"Hash {hash_val}:"
            f" {group['input_gens_str']} ({len(group['configs'])} targets)"
        )

    return hash_groups


def process_all_experiments(
    eval_dir: Path, hash_groups: Dict[str, List[Dict]]
) -> List[ExperimentReport]:
    """Step 3: Process ALL experiments (complete and incomplete)"""
    logger.info("Step 3: Processing ALL experiments (complete and incomplete)...")

    reports = []

    for config_hash, group in hash_groups.items():
        input_gens = group["input_gens"]

        for config_data in group["configs"]:
            target = config_data["target"]
            harnesses = config_data["harnesses"]

            # Check if stdout exists (experiment started)
            stdout_file = eval_dir / "stdout" / target / f"{config_hash}.txt"
            has_stdout = stdout_file.exists()

            # Check if results exist (experiment completed)
            results_dir = eval_dir / "results" / config_hash / target
            eval_result_dir = (
                results_dir / "eval_result" if results_dir.exists() else None
            )

            # Process each harness
            for harness_name in harnesses:
                experiment_name = f"{config_hash}/{target}/{harness_name}"

                # Determine completion status
                is_complete = False
                reports_path = None
                base_path = None

                if eval_result_dir and eval_result_dir.exists():
                    reports_path = eval_result_dir / "reports" / harness_name
                    if reports_path.exists():
                        linux_path = reports_path / "linux"
                        if linux_path.exists():
                            is_complete = True
                            base_path = results_dir

                # Calculate experiment duration, start time, and end time
                duration = None
                start_time = None
                end_time = None

                if has_stdout:
                    if is_complete:
                        # Complete experiment: try to get full duration and timing
                        duration, start_time, end_time = calculate_experiment_duration(
                            eval_dir, target, config_hash, harness_name
                        )
                    else:
                        # Incomplete experiment: get start time only
                        start_time_timestamp = _parse_start_time_from_logs(stdout_file)
                        if start_time_timestamp:
                            start_time = _format_start_time(start_time_timestamp)
                        duration = "Not finished"
                        end_time = "Not finished"
                else:
                    # No stdout: experiment not started
                    start_time = "Not started"
                    duration = "Not started"
                    end_time = "Not started"

                # Create experiment report
                report = ExperimentReport(
                    experiment_name=experiment_name,
                    target=target,
                    harness_name=harness_name,
                    config_hash=config_hash,
                    input_gens=input_gens,
                    base_path=base_path or Path(),  # Use empty path for incomplete
                    reports_path=reports_path
                    or Path(),  # Use empty path for incomplete
                    experiment_duration=duration,
                    experiment_start_time=start_time,
                    experiment_end_time=end_time,
                    is_complete=is_complete,
                    has_stdout=has_stdout,
                )

                reports.append(report)

                status = (
                    "complete"
                    if is_complete
                    else ("started" if has_stdout else "not started")
                )
                logger.debug(
                    f"Found experiment: {target}/{harness_name} (hash: {config_hash}) -"
                    f" {status}"
                )

    complete_count = sum(1 for r in reports if r.is_complete)
    logger.info(
        f"Processed {len(reports)} total experiments ({complete_count} complete,"
        f" {len(reports) - complete_count} incomplete)"
    )
    return reports


def process_experiments(
    eval_dir: Path, hash_groups: Dict[str, List[Dict]]
) -> List[ExperimentReport]:
    """Step 3: Process each experiment and check for results (LEGACY - only complete experiments)"""
    logger.info("Step 3: Processing experiments and checking for results...")

    reports = []

    for config_hash, group in hash_groups.items():
        input_gens = group["input_gens"]

        for config_data in group["configs"]:
            target = config_data["target"]
            harnesses = config_data["harnesses"]

            # Check if results exist
            results_dir = eval_dir / "results" / config_hash / target
            if not results_dir.exists():
                logger.debug(f"No results for {target} (hash: {config_hash})")
                continue

            eval_result_dir = results_dir / "eval_result"
            if not eval_result_dir.exists():
                logger.debug(f"No eval_result for {target} (hash: {config_hash})")
                continue

            # Process each harness
            for harness_name in harnesses:
                reports_path = eval_result_dir / "reports" / harness_name
                if not reports_path.exists():
                    logger.debug(
                        f"No reports for {target}/{harness_name} (hash: {config_hash})"
                    )
                    continue

                linux_path = reports_path / "linux"
                if not linux_path.exists():
                    logger.debug(
                        f"No linux reports for {target}/{harness_name} (hash:"
                        f" {config_hash})"
                    )
                    continue

                # Create experiment report
                experiment_name = f"{config_hash}/{target}/{harness_name}"

                # Calculate experiment duration, start time, and end time from stdout file
                duration, start_time, end_time = calculate_experiment_duration(
                    eval_dir, target, config_hash, harness_name
                )

                report = ExperimentReport(
                    experiment_name=experiment_name,
                    target=target,
                    harness_name=harness_name,
                    config_hash=config_hash,
                    input_gens=input_gens,
                    base_path=results_dir,
                    reports_path=reports_path,
                    experiment_duration=duration,
                    experiment_start_time=start_time,
                    experiment_end_time=end_time,
                )

                reports.append(report)
                logger.debug(
                    f"Found experiment: {target}/{harness_name} (hash: {config_hash})"
                )

    logger.info(f"Processed {len(reports)} experiments with results")
    return reports


def extract_dedup_token(crash_log_content: str) -> Optional[str]:
    """Extract DEDUP_TOKEN from crash log content"""
    for line in crash_log_content.splitlines():
        if line.startswith("DEDUP_TOKEN: "):
            return line.replace("DEDUP_TOKEN: ", "").strip()
    return None


def get_target_base_path(target: str, multilang_root: Path = None) -> Path:
    """Convert target like 'aixcc/c/mock-c' to path relative to multilang root"""
    if multilang_root is None:
        # Fallback: From local-testing/mlla_e2e/experiments.py, go up to CRS-multilang root
        current_file = Path(__file__)
        multilang_root = current_file.parent.parent.parent

    return multilang_root / "benchmarks" / "projects" / target


def convert_repo_url_to_web(repo_url: str) -> str:
    """Convert git@ URLs to https:// URLs for web browsing"""
    if repo_url.startswith("git@github.com:"):
        # Convert git@github.com:Team-Atlanta/mock-c.git -> https://github.com/Team-Atlanta/mock-c
        repo_path = repo_url.replace("git@github.com:", "").replace(".git", "")
        return f"https://github.com/{repo_path}"
    elif repo_url.startswith("https://github.com/"):
        # Already a web URL, just remove .git if present
        return repo_url.replace(".git", "")
    else:
        # For other URL formats, return as-is
        return repo_url


def discover_aixcc_targets() -> List[str]:
    """Discover all AIXCC targets in benchmarks/projects/aixcc/"""
    targets = []

    # Get the aixcc directory
    current_file = Path(__file__)
    crs_root = current_file.parent.parent.parent
    aixcc_dir = crs_root / "benchmarks" / "projects" / "aixcc"

    if not aixcc_dir.exists():
        logger.warning(f"AIXCC directory not found: {aixcc_dir}")
        return targets

    # Scan for language directories
    for lang_dir in aixcc_dir.iterdir():
        if not lang_dir.is_dir():
            continue

        # Scan for project directories within each language
        for project_dir in lang_dir.iterdir():
            if not project_dir.is_dir():
                continue

            # Check if it has the required files
            project_yaml = project_dir / "project.yaml"
            config_yaml = project_dir / ".aixcc" / "config.yaml"

            if project_yaml.exists() and config_yaml.exists():
                target = f"aixcc/{lang_dir.name}/{project_dir.name}"
                targets.append(target)
                logger.debug(f"Found AIXCC target: {target}")

    logger.info(f"Discovered {len(targets)} AIXCC targets")
    return targets


def load_target_info(target: str, multilang_root: Path = None) -> Optional[TargetInfo]:
    """Load complete target information from project.yaml and config.yaml"""
    try:
        target_path = get_target_base_path(target, multilang_root)

        if not target_path.exists():
            logger.warning(f"Target path not found: {target_path}")
            return None

        # Parse target components
        target_parts = target.split("/")
        if len(target_parts) < 3 or target_parts[0] != "aixcc":
            logger.warning(f"Invalid target format: {target}")
            return None

        language = target_parts[1]
        project_name = target_parts[2]

        # Load project.yaml
        project_yaml_path = target_path / "project.yaml"
        if not project_yaml_path.exists():
            logger.warning(f"project.yaml not found: {project_yaml_path}")
            return None

        with open(project_yaml_path, "r") as f:
            project_data = yaml.safe_load(f)

        repo_url = project_data.get("main_repo", "")
        repo_url_web = convert_repo_url_to_web(repo_url)

        # Load config.yaml
        config_yaml_path = target_path / ".aixcc" / "config.yaml"
        if not config_yaml_path.exists():
            logger.warning(f"config.yaml not found: {config_yaml_path}")
            return None

        with open(config_yaml_path, "r") as f:
            config_data = yaml.safe_load(f)

        # Extract harnesses and CPVs
        harnesses = []
        harness_info = []
        cpvs = []

        # Get base commit for source repo links
        base_commit = config_data.get("full_mode", {}).get("base_commit", "main")

        harness_files = config_data.get("harness_files", [])
        for harness_file in harness_files:
            harness_name = harness_file.get("name", "")
            harness_path = harness_file.get("path", "")

            if harness_name:
                harnesses.append(harness_name)

                # Resolve harness file URL
                resolved_url = ""
                if harness_path:
                    if harness_path.startswith("$PROJECT/"):
                        # $PROJECT refers to the target repo (Team-Atlanta/oss-fuzz)
                        project_path = harness_path.replace("$PROJECT/", "")
                        resolved_url = f"https://github.com/Team-Atlanta/oss-fuzz/blob/main/projects/{target}/{project_path}"
                    elif harness_path.startswith("$REPO/") and repo_url_web:
                        # $REPO refers to the source repo - use base_commit
                        repo_path = harness_path.replace("$REPO/", "")
                        resolved_url = f"{repo_url_web}/blob/{base_commit}/{repo_path}"

                harness_info.append(
                    HarnessInfo(
                        name=harness_name,
                        path=harness_path,
                        resolved_url=resolved_url,
                    )
                )

            # Extract CPVs for this harness
            harness_cpvs = harness_file.get("cpvs", [])
            for cpv_data in harness_cpvs:
                cpv_name = cpv_data.get("name", "")
                sanitizer = cpv_data.get("sanitizer", "")
                error_token = cpv_data.get("error_token", "")

                if cpv_name:
                    # Build paths to PoV and crash log files
                    pov_file_path = (
                        target_path / ".aixcc" / "povs" / harness_name / cpv_name
                    )
                    crash_log_path = (
                        target_path
                        / ".aixcc"
                        / "crash_logs"
                        / harness_name
                        / f"{cpv_name}.log"
                    )

                    # Load crash log content
                    crash_log_content = ""
                    if crash_log_path.exists():
                        try:
                            with open(
                                crash_log_path, "r", encoding="utf-8", errors="replace"
                            ) as f:
                                crash_log_content = f.read()
                        except Exception as e:
                            logger.warning(
                                f"Failed to read crash log {crash_log_path}: {e}"
                            )

                    # Extract DEDUP_TOKEN from crash log content
                    dedup_token = extract_dedup_token(crash_log_content)

                    cpv = TargetCPV(
                        name=cpv_name,
                        harness_name=harness_name,
                        sanitizer=sanitizer,
                        error_token=error_token,
                        pov_file_path=pov_file_path,
                        crash_log_path=crash_log_path,
                        crash_log_content=crash_log_content,
                        dedup_token=dedup_token,
                    )
                    cpvs.append(cpv)

        target_info = TargetInfo(
            target=target,
            language=language,
            project_name=project_name,
            repo_url=repo_url,
            repo_url_web=repo_url_web,
            harnesses=harnesses,
            harness_info=harness_info,
            cpvs=cpvs,
            base_commit=base_commit,
        )

        logger.debug(
            f"Loaded target info for {target}: {len(harnesses)} harnesses,"
            f" {len(cpvs)} CPVs"
        )
        return target_info

    except Exception as e:
        logger.warning(f"Failed to load target info for {target}: {e}")
        return None


def parse_crash_json(crash_json_path: Path) -> List[FoundPoV]:
    """Parse crash.json file to extract found PoVs"""
    found_povs = []

    if not crash_json_path.exists():
        logger.debug(f"crash.json not found: {crash_json_path}")
        return found_povs

    try:
        with open(crash_json_path, "r", encoding="utf-8") as f:
            crash_data = json.load(f)

        if not isinstance(crash_data, list):
            logger.warning(
                f"Expected list in crash.json, got {type(crash_data)}:"
                f" {crash_json_path}"
            )
            return found_povs

        for pov_entry in crash_data:
            if not isinstance(pov_entry, dict):
                continue

            pov_id = pov_entry.get("PoV", "")
            status = pov_entry.get("Status", "")
            finder = pov_entry.get("Finder", "")
            harness = pov_entry.get("Harness", "")
            sanitizer_output = pov_entry.get("Sanitizer Output", "")
            uuid = pov_entry.get("UUID", "")

            # Parse time - handle both string and int
            time_str = pov_entry.get("Time (s)", "0")
            try:
                time_seconds = int(float(str(time_str)))
            except (ValueError, TypeError):
                time_seconds = 0

            if pov_id:  # Only add if we have a valid PoV ID
                found_pov = FoundPoV(
                    pov_id=pov_id,
                    status=status,
                    finder=finder,
                    harness=harness,
                    sanitizer_output=sanitizer_output,
                    time_seconds=time_seconds,
                    uuid=uuid,
                )
                found_povs.append(found_pov)

        logger.debug(f"Parsed {len(found_povs)} PoVs from {crash_json_path}")

    except Exception as e:
        logger.warning(f"Failed to parse crash.json {crash_json_path}: {e}")

    return found_povs


def match_povs_to_cpvs(
    found_povs: List[FoundPoV],
    target_cpvs: List[TargetCPV],
    harness_name: str,
    povs_dir: Path,
) -> None:
    """Match found PoVs to expected CPVs using three-tier matching strategy"""
    # Get CPVs for this harness
    harness_cpvs = [cpv for cpv in target_cpvs if cpv.harness_name == harness_name]

    logger.debug(f"Found {len(harness_cpvs)} CPVs for harness {harness_name}")

    # For each found PoV, try matching using multiple strategies
    for found_pov in found_povs:
        # Tier 1: Try sanitizer_output matching first (highest priority)
        if found_pov.sanitizer_output:
            for cpv in harness_cpvs:
                if (
                    cpv.crash_log_content
                    and found_pov.sanitizer_output in cpv.crash_log_content
                ):
                    found_pov.matched_cpv = cpv.name
                    logger.debug(
                        f"PoV {found_pov.pov_id} matched CPV {cpv.name} via"
                        " sanitizer_output"
                    )
                    break

        # Tier 2: Try DEDUP_TOKEN matching if no sanitizer_output match
        if not found_pov.matched_cpv:
            crash_log_path = povs_dir / f"{found_pov.pov_id}.crash_log"

            if crash_log_path.exists():
                try:
                    with open(
                        crash_log_path, "r", encoding="utf-8", errors="replace"
                    ) as f:
                        crash_log_content = f.read()

                    # Extract DEDUP_TOKEN from PoV crash log
                    pov_dedup_token = extract_dedup_token(crash_log_content)

                    if pov_dedup_token:
                        for cpv in harness_cpvs:
                            if cpv.dedup_token and cpv.dedup_token == pov_dedup_token:
                                found_pov.matched_cpv = cpv.name
                                logger.debug(
                                    f"PoV {found_pov.pov_id} matched CPV {cpv.name} via"
                                    f" DEDUP_TOKEN: {pov_dedup_token}"
                                )
                                break

                    # Tier 3: Fallback to error_token matching if no DEDUP_TOKEN match
                    if not found_pov.matched_cpv:
                        for cpv in harness_cpvs:
                            if cpv.error_token and cpv.error_token in crash_log_content:
                                found_pov.matched_cpv = cpv.name
                                logger.debug(
                                    f"PoV {found_pov.pov_id} matched CPV {cpv.name} via"
                                    f" error_token: {cpv.error_token}"
                                )
                                break

                except Exception as e:
                    logger.warning(f"Failed to read crash log {crash_log_path}: {e}")
            else:
                logger.debug(f"Crash log not found: {crash_log_path}")


def load_litellm_metadata(
    eval_dir: Path, target: str, config_hash: str
) -> Optional[LiteLLMStats]:
    """Load LiteLLM usage statistics from metadata file"""
    metadata_file = eval_dir / "metadata" / target / f"{config_hash}.json"

    if not metadata_file.exists():
        logger.debug(f"LiteLLM metadata not found: {metadata_file}")
        return None

    try:
        with open(metadata_file, "r") as f:
            metadata = json.load(f)

        # Get the key_alias for this specific experiment
        key_info = metadata.get("key_info", {})
        info = key_info.get("info", {})
        target_key_alias = info.get("key_alias", "")

        if not target_key_alias:
            logger.warning(f"No key_alias found in metadata for {target}/{config_hash}")
            return None

        # Initialize aggregated metrics
        total_metrics = {
            "spend": 0.0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "total_tokens": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "api_requests": 0,
        }

        # Process each date's results
        user_activity = metadata.get("user_activity", {})
        results = user_activity.get("results", [])

        for date_result in results:
            date = date_result.get("date", "")
            breakdown = date_result.get("breakdown", {})
            api_keys = breakdown.get("api_keys", {})

            # Search through all API keys for this date
            for api_key_hash, api_key_data in api_keys.items():
                key_metadata = api_key_data.get("metadata", {})
                key_alias = key_metadata.get("key_alias", "")

                # Check if this API key matches our target
                if key_alias == target_key_alias:
                    # Found the matching API key for this date
                    metrics = api_key_data.get("metrics", {})

                    # Aggregate the metrics
                    for metric_name in total_metrics.keys():
                        total_metrics[metric_name] += metrics.get(metric_name, 0)

                    logger.debug(
                        f"Found matching key_alias {target_key_alias} for date {date}"
                    )
                    break  # Found the key for this date, move to next date

        # Create LiteLLMStats with aggregated values
        stats = LiteLLMStats(
            total_spend=float(total_metrics["spend"]),
            total_prompt_tokens=int(total_metrics["prompt_tokens"]),
            total_completion_tokens=int(total_metrics["completion_tokens"]),
            total_tokens=int(total_metrics["total_tokens"]),
            total_api_requests=int(total_metrics["api_requests"]),
            total_successful_requests=int(total_metrics["successful_requests"]),
            total_failed_requests=int(total_metrics["failed_requests"]),
            total_cache_read_input_tokens=int(total_metrics["cache_read_input_tokens"]),
            total_cache_creation_input_tokens=int(
                total_metrics["cache_creation_input_tokens"]
            ),
        )

        logger.debug(
            f"Loaded LiteLLM stats for {target}/{config_hash} (key_alias:"
            f" {target_key_alias}): ${stats.total_spend:.4f},"
            f" {stats.total_tokens} tokens"
        )
        return stats

    except Exception as e:
        logger.warning(f"Failed to load LiteLLM metadata from {metadata_file}: {e}")
        return None


def analyze_experiment_results(report: ExperimentReport) -> ExperimentStats:
    """Analyze experiment results to count PoVs with real data"""
    expected_cpvs = 0
    found_povs = 0
    matched_povs = 0
    unintended_povs = 0
    missing_cpvs = 0
    found_pov_details = []

    # Count expected CPVs for this harness from target info
    if report.target_info:
        for cpv in report.target_info.cpvs:
            if cpv.harness_name == report.harness_name:
                expected_cpvs += 1

    # Parse crash.json to get found PoVs
    crash_json_path = report.reports_path / "linux" / "crash.json"
    found_pov_details = parse_crash_json(crash_json_path)
    found_povs = len(found_pov_details)

    # Match found PoVs to expected CPVs
    if report.target_info and found_pov_details:
        # Calculate povs directory path - it's at eval_result/povs/{harness}/ not reports/.../povs/
        eval_result_dir = report.base_path / "eval_result"
        povs_dir = eval_result_dir / "povs" / report.harness_name

        match_povs_to_cpvs(
            found_pov_details, report.target_info.cpvs, report.harness_name, povs_dir
        )

        # Count matches and unintended
        matched_cpv_names = set()
        for pov in found_pov_details:
            if pov.matched_cpv:
                matched_povs += 1
                matched_cpv_names.add(pov.matched_cpv)
            else:
                unintended_povs += 1

        # Calculate missing CPVs (expected but not found)
        missing_cpvs = expected_cpvs - len(matched_cpv_names)

    logger.debug(
        f"Experiment {report.experiment_name}: {expected_cpvs} expected,"
        f" {found_povs} found, {matched_povs} matched, {unintended_povs} unintended,"
        f" {missing_cpvs} missing"
    )

    return ExperimentStats(
        expected_cpvs=expected_cpvs,
        found_povs=found_povs,
        matched_povs=matched_povs,
        unintended_povs=unintended_povs,
        missing_cpvs=missing_cpvs,
        found_pov_details=found_pov_details,
    )


def discover_available_dates(root_eval_dir: Path) -> list[str]:
    """Discover all eval directories (any format) sorted by creation time"""
    eval_dirs = []
    if not root_eval_dir.exists():
        return []

    for item in root_eval_dir.iterdir():
        if item.is_dir():
            # Only check if it has configs directory to confirm it's an eval directory
            if (item / "configs").exists():
                try:
                    # Get directory birth time using stat command
                    result = subprocess.run(
                        ["stat", "-c", "%W", str(item)],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )

                    if result.returncode == 0:
                        birth_time = float(result.stdout.strip())
                        # Birth time of 0 means not available, fallback to mtime
                        if birth_time == 0:
                            birth_time = item.stat().st_mtime
                    else:
                        # Fallback to modification time if stat fails
                        birth_time = item.stat().st_mtime

                    eval_dirs.append((item.name, birth_time))

                except Exception as e:
                    logger.debug(f"Failed to get birth time for {item}: {e}")
                    # Fallback to modification time
                    birth_time = item.stat().st_mtime
                    eval_dirs.append((item.name, birth_time))

    # Sort by birth time (newest first)
    eval_dirs.sort(key=lambda x: x[1], reverse=True)

    # Return just the directory names
    return [name for name, _ in eval_dirs]


def resolve_date(root_eval_dir: Path, date_str: str) -> str | None:
    """Resolve 'latest' or validate specific date"""
    available_dates = discover_available_dates(root_eval_dir)
    if not available_dates:
        return None

    if date_str == "latest":
        return available_dates[0]
    elif date_str in available_dates:
        return date_str
    else:
        return None


def get_eval_dir_for_date(root_eval_dir: Path, date: str) -> Path:
    """Get the eval_dir path for a specific date"""
    return root_eval_dir / date


def load_git_metadata(eval_dir: Path) -> Optional[GitInfo]:
    """Load git information from metadata.json"""
    metadata_file = eval_dir / "metadata.json"
    if not metadata_file.exists():
        logger.debug(f"Git metadata not found: {metadata_file}")
        return None

    try:
        with open(metadata_file, "r") as f:
            metadata = json.load(f)

        git_info_data = metadata.get("git_info", {})
        if not git_info_data:
            logger.warning(f"No git_info found in metadata: {metadata_file}")
            return None

        # Extract main commit info
        main_commit = git_info_data.get("main_commit", "")
        main_commit_date = git_info_data.get("main_commit_date_utc", "")

        # Extract submodules
        submodules = []
        submodules_data = git_info_data.get("submodules_with_dates", [])
        for submodule_data in submodules_data:
            submodule = GitSubmodule(
                path=submodule_data.get("path", ""),
                commit=submodule_data.get("commit", ""),
                date_utc=submodule_data.get("date_utc", ""),
            )
            submodules.append(submodule)

        # Extract dirty status
        dirty = git_info_data.get("dirty", False)
        dirty_files = git_info_data.get("dirty_files", None)

        git_info = GitInfo(
            main_commit=main_commit,
            main_commit_date=main_commit_date,
            submodules=submodules,
            dirty=dirty,
            dirty_files=dirty_files,
        )

        logger.debug(
            f"Loaded git info: main={main_commit[:8]}, {len(submodules)} submodules,"
            f" dirty={dirty}"
        )
        return git_info

    except Exception as e:
        logger.warning(f"Failed to load git metadata from {metadata_file}: {e}")
        return None


def parse_seed_metadata(metadata_path: Path) -> Optional[str]:
    """Parse .{hash}.metadata JSON file to extract finder name"""
    if not metadata_path.exists():
        logger.debug(f"Metadata file not found: {metadata_path}")
        return None

    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        finder = metadata.get("finder", "")
        if finder:
            # Normalize finder name: if it contains dots, take only first two parts
            if "." in finder:
                parts = finder.split(".")
                if len(parts) >= 2:
                    normalized_finder = f"{parts[0]}.{parts[1]}"
                    logger.debug(
                        f"Normalized finder '{finder}' -> '{normalized_finder}' in"
                        f" {metadata_path}"
                    )
                    return normalized_finder
                else:
                    logger.debug(f"Found finder '{finder}' in {metadata_path}")
                    return finder
            else:
                logger.debug(f"Found finder '{finder}' in {metadata_path}")
                return finder
        else:
            logger.debug(f"No finder field in metadata: {metadata_path}")
            return None

    except Exception as e:
        logger.warning(f"Failed to parse metadata {metadata_path}: {e}")
        return None


def load_corpus_directory(corpus_dir: Path, corpus_type: str) -> List[SeedInfo]:
    """Load all seeds and their metadata from a corpus directory"""
    seeds = []

    if not corpus_dir.exists():
        logger.debug(f"Corpus directory not found: {corpus_dir}")
        return seeds

    logger.debug(f"Loading {corpus_type} corpus from: {corpus_dir}")

    # Find all files that are not metadata files
    for file_path in corpus_dir.iterdir():
        if file_path.is_file() and not file_path.name.startswith("."):
            # This is a seed file, look for corresponding metadata
            seed_hash = file_path.name
            metadata_path = corpus_dir / f".{seed_hash}.metadata"

            # Parse metadata to get finder
            finder = parse_seed_metadata(metadata_path)
            if finder:
                seed_info = SeedInfo(
                    hash=seed_hash,
                    finder=finder,
                    corpus_type=corpus_type,
                    file_path=file_path,
                    metadata_path=metadata_path,
                )
                seeds.append(seed_info)
                logger.debug(
                    f"Loaded seed {seed_hash} from {corpus_type} (finder: {finder})"
                )
            else:
                logger.debug(f"Skipping seed {seed_hash} - no valid metadata")

    logger.debug(f"Loaded {len(seeds)} seeds from {corpus_type}")
    return seeds


def analyze_finder_statistics(
    seeds: List[SeedInfo], found_pov_details: List[FoundPoV] = None
) -> List[FinderStats]:
    """Generate per-finder statistics from seed list with matched/unintended PoV breakdown"""
    finder_counts = {}

    # Create a mapping of PoV ID to matched status if found_pov_details is provided
    pov_match_status = {}
    if found_pov_details:
        for pov in found_pov_details:
            pov_match_status[pov.pov_id] = pov.matched_cpv is not None

    # Count seeds by finder and corpus type
    for seed in seeds:
        finder = seed.finder
        if finder not in finder_counts:
            finder_counts[finder] = {
                "pov": 0,
                "matched_pov": 0,
                "unintended_pov": 0,
                "others_corpus": 0,
                "uniafl_corpus": 0,
            }

        if seed.corpus_type == "pov":
            finder_counts[finder]["pov"] += 1

            # Determine if this PoV is matched or unintended based on seed hash
            if pov_match_status and seed.hash in pov_match_status:
                if pov_match_status[seed.hash]:
                    finder_counts[finder]["matched_pov"] += 1
                else:
                    finder_counts[finder]["unintended_pov"] += 1
            else:
                # If we can't determine the status, count as unintended
                finder_counts[finder]["unintended_pov"] += 1

        elif seed.corpus_type == "others_corpus":
            finder_counts[finder]["others_corpus"] += 1
        elif seed.corpus_type == "uniafl_corpus":
            finder_counts[finder]["uniafl_corpus"] += 1

    # Generate FinderStats objects
    finder_stats = []
    for finder_name, counts in finder_counts.items():
        total_seeds = counts["pov"] + counts["others_corpus"] + counts["uniafl_corpus"]

        stats = FinderStats(
            finder_name=finder_name,
            pov_count=counts["pov"],
            matched_pov_count=counts["matched_pov"],
            unintended_pov_count=counts["unintended_pov"],
            others_corpus_count=counts["others_corpus"],
            uniafl_corpus_count=counts["uniafl_corpus"],
            total_seeds=total_seeds,
        )
        finder_stats.append(stats)

        logger.debug(
            f"Finder '{finder_name}': {counts['pov']} PoVs"
            f" ({counts['matched_pov']} matched,"
            f" {counts['unintended_pov']} unintended),"
            f" {counts['others_corpus']} others_corpus,"
            f" {counts['uniafl_corpus']} uniafl_corpus (total: {total_seeds})"
        )

    # Sort by total seeds descending
    finder_stats.sort(key=lambda x: x.total_seeds, reverse=True)
    return finder_stats


def load_experiment_corpus_data(
    eval_dir: Path,
    config_hash: str,
    target: str,
    harness_name: str,
    found_pov_details: List[FoundPoV] = None,
) -> Optional[CorpusAnalysis]:
    """Load complete corpus analysis for an experiment with PoV matching data"""
    import time

    start_time = time.time()
    logger.debug(
        "[CORPUS_LOAD_START] Loading corpus data for"
        f" {config_hash}/{target}/{harness_name}"
    )

    # Build path to workdir_result
    workdir_result_path = (
        eval_dir / "results" / config_hash / target / "workdir_result" / harness_name
    )

    if not workdir_result_path.exists():
        logger.debug(f"Workdir result not found: {workdir_result_path}")
        logger.debug(
            "[CORPUS_LOAD_END] No workdir for"
            f" {config_hash}/{target}/{harness_name} (took"
            f" {time.time() - start_time:.2f}s)"
        )
        return None

    logger.debug(f"Loading corpus data from: {workdir_result_path}")

    all_seeds = []

    # Load from each corpus directory
    corpus_dirs = [
        ("pov", workdir_result_path / "pov"),
        ("others_corpus", workdir_result_path / "others_corpus"),
        ("uniafl_corpus", workdir_result_path / "uniafl_corpus"),
    ]

    for corpus_type, corpus_dir in corpus_dirs:
        seeds = load_corpus_directory(corpus_dir, corpus_type)
        all_seeds.extend(seeds)

    if not all_seeds:
        logger.debug(
            "No seeds found in any corpus directory for"
            f" {config_hash}/{target}/{harness_name}"
        )
        return None

    # Generate statistics with PoV matching information
    finder_stats = analyze_finder_statistics(all_seeds, found_pov_details)

    # Calculate totals
    total_povs = sum(1 for seed in all_seeds if seed.corpus_type == "pov")
    total_others_corpus = sum(
        1 for seed in all_seeds if seed.corpus_type == "others_corpus"
    )
    total_uniafl_corpus = sum(
        1 for seed in all_seeds if seed.corpus_type == "uniafl_corpus"
    )
    unique_finders = set(seed.finder for seed in all_seeds)

    corpus_analysis = CorpusAnalysis(
        seeds=all_seeds,
        finder_stats=finder_stats,
        total_povs=total_povs,
        total_others_corpus=total_others_corpus,
        total_uniafl_corpus=total_uniafl_corpus,
        unique_finders=unique_finders,
    )

    logger.debug(
        "[CORPUS_LOAD_END] Completed corpus analysis for"
        f" {config_hash}/{target}/{harness_name}: {total_povs} PoVs,"
        f" {total_others_corpus} others_corpus, {total_uniafl_corpus} uniafl_corpus,"
        f" {len(unique_finders)} unique finders (took {time.time() - start_time:.2f}s)"
    )

    return corpus_analysis


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes}B"
    elif size_bytes < 1024 * 1024:
        return f"{round(size_bytes / 1024, 1)}KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{round(size_bytes / 1024 / 1024, 1)}MB"
    else:
        return f"{round(size_bytes / 1024 / 1024 / 1024, 1)}GB"


def discover_all_experiments(
    eval_dir: Path, multilang_root: Path = None
) -> List[ExperimentReport]:
    """Discover ALL experiments (complete and incomplete) using step-by-step approach"""
    logger.info(
        f"Scanning for ALL experiments (complete and incomplete) in: {eval_dir}"
    )

    # Step 1: Fetch config files
    configs = fetch_config_files(eval_dir)
    if not configs:
        return []

    # Step 2: Aggregate by hash (input generation combinations)
    hash_groups = aggregate_by_hash(configs)

    # Step 3: Process ALL experiments (complete and incomplete)
    reports = process_all_experiments(eval_dir, hash_groups)

    # Step 4: Load git metadata once for all experiments from this eval_dir
    git_info = load_git_metadata(eval_dir)

    # Step 5: Enhance reports with target information, git info, LiteLLM stats, and corpus analysis
    for report in reports:
        # Assign git info to all reports from this eval_dir
        report.git_info = git_info

        # Load target info if it's an AIXCC target
        if report.target.startswith("aixcc/"):
            report.target_info = load_target_info(report.target, multilang_root)
            # Only analyze results for complete experiments
            if report.is_complete:
                report.experiment_stats = analyze_experiment_results(report)

        # Load LiteLLM metadata for all experiments (only works for complete ones)
        if report.is_complete:
            report.litellm_stats = load_litellm_metadata(
                eval_dir, report.target, report.config_hash
            )

        # Load corpus analysis for all experiments (both complete and incomplete)
        # Pass found PoV details if available for matched/unintended classification
        found_pov_details = None
        if report.experiment_stats and report.experiment_stats.found_pov_details:
            found_pov_details = report.experiment_stats.found_pov_details

        report.corpus_analysis = load_experiment_corpus_data(
            eval_dir,
            report.config_hash,
            report.target,
            report.harness_name,
            found_pov_details,
        )

    return reports


def discover_experiments(
    eval_dir: Path, multilang_root: Path = None
) -> List[ExperimentReport]:
    """Discover all experiment reports using step-by-step approach (LEGACY - only complete experiments)"""
    logger.info(f"Scanning for experiments in: {eval_dir}")

    # Step 1: Fetch config files
    configs = fetch_config_files(eval_dir)
    if not configs:
        return []

    # Step 2: Aggregate by hash (input generation combinations)
    hash_groups = aggregate_by_hash(configs)

    # Step 3: Process each experiment
    reports = process_experiments(eval_dir, hash_groups)

    # Step 4: Enhance reports with target information and LiteLLM stats
    for report in reports:
        # Load target info if it's an AIXCC target
        if report.target.startswith("aixcc/"):
            report.target_info = load_target_info(report.target, multilang_root)
            report.experiment_stats = analyze_experiment_results(report)

        # Load LiteLLM metadata for all experiments
        report.litellm_stats = load_litellm_metadata(
            eval_dir, report.target, report.config_hash
        )

    return reports
