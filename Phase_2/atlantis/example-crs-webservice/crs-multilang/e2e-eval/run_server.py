#!/usr/bin/env python3
import argparse
import ssl
import threading
import time
from functools import wraps
from pathlib import Path
from urllib.parse import quote

from flask import (
    Flask,
    Response,
    redirect,
    render_template,
    request,
    send_from_directory,
)
from loguru import logger

from experiments import (
    discover_all_experiments,
    discover_available_dates,
    discover_experiments,
    format_file_size,
    get_eval_dir_for_date,
    resolve_date,
)
from generate_zips import ZipGenerator


def format_tokens(tokens):
    """Format token count with K/M suffixes"""
    if tokens == 0:
        return "-"
    elif tokens >= 1_000_000:
        return f"{tokens / 1_000_000:.1f}M"
    elif tokens >= 1_000:
        return f"{tokens / 1_000:.0f}K"
    else:
        return str(tokens)


def format_cost(cost):
    """Format cost to 2 decimal places"""
    if cost == 0:
        return "-"
    else:
        return f"${cost:.2f}"


def build_experiment_mappings(reports):
    """Build all experiment mappings and combinations in a single pass"""
    hash_to_input_gens = {}
    input_gens_to_hash = {}
    hash_counts = {}

    # Single pass through reports
    for report in reports:
        input_gens_str = ", ".join(report.input_gens)
        hash_to_input_gens[report.config_hash] = input_gens_str
        input_gens_to_hash[input_gens_str] = report.config_hash
        hash_counts[report.config_hash] = hash_counts.get(report.config_hash, 0) + 1

    # Build unique combinations from the mappings
    unique_combinations = []
    for config_hash, input_gens_str in hash_to_input_gens.items():
        unique_combinations.append(
            {
                "hash": config_hash,
                "input_gens": input_gens_str,
                "count": hash_counts[config_hash],
            }
        )

    unique_combinations.sort(key=lambda x: x["input_gens"])
    return hash_to_input_gens, input_gens_to_hash, unique_combinations


def calculate_aggregate_stats(reports):
    """Calculate aggregate PoV and LiteLLM statistics from reports using capped logic"""
    total_capped_matched = 0
    total_expected = 0
    total_extra_povs = 0
    total_unintended = 0
    total_finished = 0

    # LiteLLM aggregates
    total_spend = 0.0
    total_tokens = 0
    total_requests = 0
    total_successful_requests = 0
    total_failed_requests = 0
    total_cache_read_tokens = 0

    # Track processed (config_hash, target) pairs to avoid double-counting LiteLLM data
    processed_litellm_pairs = set()

    for report in reports:
        # Count finished experiments
        if hasattr(report, "is_complete") and report.is_complete:
            total_finished += 1

        # PoV statistics (per experiment) - only count complete experiments
        if (
            hasattr(report, "experiment_stats")
            and report.experiment_stats
            and hasattr(report, "is_complete")
            and report.is_complete
        ):
            matched = report.experiment_stats.matched_povs or 0
            expected = report.experiment_stats.expected_cpvs or 0

            # Calculate capped matched and extras per experiment
            capped_matched = min(matched, expected)
            extra_povs = max(0, matched - expected)

            total_capped_matched += capped_matched
            total_expected += expected
            total_extra_povs += extra_povs
            total_unintended += report.experiment_stats.unintended_povs or 0

        # LiteLLM statistics (per target within each config_hash)
        # Each target has its own metadata file, so we need to sum across all targets
        target_config_pair = (report.config_hash, report.target)
        if (
            hasattr(report, "litellm_stats")
            and report.litellm_stats
            and target_config_pair not in processed_litellm_pairs
        ):

            total_spend += report.litellm_stats.total_spend or 0.0
            total_tokens += report.litellm_stats.total_tokens or 0
            total_requests += report.litellm_stats.total_api_requests or 0
            total_successful_requests += (
                report.litellm_stats.total_successful_requests or 0
            )
            total_failed_requests += report.litellm_stats.total_failed_requests or 0
            total_cache_read_tokens += (
                report.litellm_stats.total_cache_read_input_tokens or 0
            )

            # Mark this (config_hash, target) pair as processed
            processed_litellm_pairs.add(target_config_pair)

    overall_success_rate = round(
        (total_capped_matched / total_expected * 100) if total_expected > 0 else 0
    )

    return {
        "total_capped_matched": total_capped_matched,
        "total_expected": total_expected,
        "total_extra_povs": total_extra_povs,
        "total_unintended": total_unintended,
        "total_finished": total_finished,
        "overall_success_rate": overall_success_rate,
        # LiteLLM totals
        "total_spend": total_spend,
        "total_tokens": total_tokens,
        "total_requests": total_requests,
        "total_successful_requests": total_successful_requests,
        "total_failed_requests": total_failed_requests,
        "total_cache_read_tokens": total_cache_read_tokens,
    }


def calculate_aggregate_finder_stats(input_gen_stats):
    """Calculate aggregate finder statistics across all combinations with matched/unintended breakdown"""
    all_matched_pov_finder_totals = {}
    all_unintended_pov_finder_totals = {}
    all_uniafl_finder_totals = {}

    for combo_stats in input_gen_stats:
        # Aggregate matched PoV finders
        for finder_name, count in combo_stats.get("matched_pov_finders", []):
            if finder_name in all_matched_pov_finder_totals:
                all_matched_pov_finder_totals[finder_name] += count
            else:
                all_matched_pov_finder_totals[finder_name] = count

        # Aggregate unintended PoV finders
        for finder_name, count in combo_stats.get("unintended_pov_finders", []):
            if finder_name in all_unintended_pov_finder_totals:
                all_unintended_pov_finder_totals[finder_name] += count
            else:
                all_unintended_pov_finder_totals[finder_name] = count

        # Aggregate UniAFL finders
        for finder_name, count in combo_stats.get("uniafl_finders", []):
            if finder_name in all_uniafl_finder_totals:
                all_uniafl_finder_totals[finder_name] += count
            else:
                all_uniafl_finder_totals[finder_name] = count

    # Sort alphabetically
    all_matched_pov_finders = sorted(all_matched_pov_finder_totals.items())
    all_unintended_pov_finders = sorted(all_unintended_pov_finder_totals.items())
    all_uniafl_finders = sorted(all_uniafl_finder_totals.items())

    return all_matched_pov_finders, all_unintended_pov_finders, all_uniafl_finders


def aggregate_finder_stats_for_combination(reports_for_combination):
    """Aggregate finder statistics by corpus type for a combination with matched/unintended breakdown"""
    matched_pov_finder_totals = {}  # finder_name -> matched_pov_count
    unintended_pov_finder_totals = {}  # finder_name -> unintended_pov_count
    uniafl_finder_totals = {}  # finder_name -> uniafl_seed_count

    for report in reports_for_combination:
        if report.corpus_analysis:
            for finder_stat in report.corpus_analysis.finder_stats:
                finder_name = finder_stat.finder_name
                matched_pov_count = finder_stat.matched_pov_count
                unintended_pov_count = finder_stat.unintended_pov_count
                uniafl_count = finder_stat.uniafl_corpus_count

                # Aggregate matched PoV counts
                if matched_pov_count > 0:
                    if finder_name in matched_pov_finder_totals:
                        matched_pov_finder_totals[finder_name] += matched_pov_count
                    else:
                        matched_pov_finder_totals[finder_name] = matched_pov_count

                # Aggregate unintended PoV counts
                if unintended_pov_count > 0:
                    if finder_name in unintended_pov_finder_totals:
                        unintended_pov_finder_totals[
                            finder_name
                        ] += unintended_pov_count
                    else:
                        unintended_pov_finder_totals[finder_name] = unintended_pov_count

                # Aggregate UniAFL counts
                if uniafl_count > 0:
                    if finder_name in uniafl_finder_totals:
                        uniafl_finder_totals[finder_name] += uniafl_count
                    else:
                        uniafl_finder_totals[finder_name] = uniafl_count

    # Sort alphabetically by finder name
    matched_pov_finders = sorted(matched_pov_finder_totals.items())
    unintended_pov_finders = sorted(unintended_pov_finder_totals.items())
    uniafl_finders = sorted(uniafl_finder_totals.items())

    return matched_pov_finders, unintended_pov_finders, uniafl_finders


def calculate_input_gen_stats(reports, hash_to_input_gens):
    """Calculate per-input-generator combination statistics"""
    combo_stats = {}
    # Track which (config_hash, target) pairs we've already processed for LiteLLM stats
    processed_litellm_pairs = {}
    # Group reports by input generator combination for finder aggregation
    reports_by_combination = {}

    for report in reports:
        input_gens_str = hash_to_input_gens.get(report.config_hash, "Unknown")

        if input_gens_str not in combo_stats:
            combo_stats[input_gens_str] = {
                "input_gens": input_gens_str,
                "experiment_count": 0,
                "finished_count": 0,
                "capped_matched": 0,
                "expected": 0,
                "extra_povs": 0,
                "unintended": 0,
                "total_found": 0,
                # LiteLLM stats
                "total_spend": 0.0,
                "total_tokens": 0,
                "total_requests": 0,
                "total_successful_requests": 0,
                "total_failed_requests": 0,
                "total_cache_read_tokens": 0,
                # Finder stats (will be populated later)
                "pov_finders": [],
                "uniafl_finders": [],
            }
            processed_litellm_pairs[input_gens_str] = set()
            reports_by_combination[input_gens_str] = []

        reports_by_combination[input_gens_str].append(report)

        # Count experiments
        combo_stats[input_gens_str]["experiment_count"] += 1

        # Count finished experiments
        if hasattr(report, "is_complete") and report.is_complete:
            combo_stats[input_gens_str]["finished_count"] += 1

        # PoV statistics (per experiment) - only count complete experiments
        if (
            hasattr(report, "experiment_stats")
            and report.experiment_stats
            and hasattr(report, "is_complete")
            and report.is_complete
        ):
            matched = report.experiment_stats.matched_povs or 0
            expected = report.experiment_stats.expected_cpvs or 0

            # Calculate capped matched (never exceeds expected) and extras per experiment
            capped_matched = min(matched, expected)
            extra_povs = max(0, matched - expected)

            combo_stats[input_gens_str]["capped_matched"] += capped_matched
            combo_stats[input_gens_str]["expected"] += expected
            combo_stats[input_gens_str]["extra_povs"] += extra_povs
            combo_stats[input_gens_str]["unintended"] += (
                report.experiment_stats.unintended_povs or 0
            )
            combo_stats[input_gens_str]["total_found"] += (
                report.experiment_stats.found_povs or 0
            )

        # LiteLLM statistics (per target within each config_hash)
        # Each target has its own metadata file, so we need to sum across all targets for each config_hash
        target_config_pair = (report.config_hash, report.target)
        if (
            hasattr(report, "litellm_stats")
            and report.litellm_stats
            and target_config_pair not in processed_litellm_pairs[input_gens_str]
        ):

            combo_stats[input_gens_str]["total_spend"] += (
                report.litellm_stats.total_spend or 0.0
            )
            combo_stats[input_gens_str]["total_tokens"] += (
                report.litellm_stats.total_tokens or 0
            )
            combo_stats[input_gens_str]["total_requests"] += (
                report.litellm_stats.total_api_requests or 0
            )
            combo_stats[input_gens_str]["total_successful_requests"] += (
                report.litellm_stats.total_successful_requests or 0
            )
            combo_stats[input_gens_str]["total_failed_requests"] += (
                report.litellm_stats.total_failed_requests or 0
            )
            combo_stats[input_gens_str]["total_cache_read_tokens"] += (
                report.litellm_stats.total_cache_read_input_tokens or 0
            )

            # Mark this (config_hash, target) pair as processed for this combination
            processed_litellm_pairs[input_gens_str].add(target_config_pair)

    # Now aggregate finder statistics for each combination
    for input_gens_str, reports_list in reports_by_combination.items():
        matched_pov_finders, unintended_pov_finders, uniafl_finders = (
            aggregate_finder_stats_for_combination(reports_list)
        )
        combo_stats[input_gens_str]["matched_pov_finders"] = matched_pov_finders
        combo_stats[input_gens_str]["unintended_pov_finders"] = unintended_pov_finders
        combo_stats[input_gens_str]["uniafl_finders"] = uniafl_finders

    # Calculate success rates and sort
    result = []
    for combo_data in combo_stats.values():
        success_rate = round(
            (combo_data["capped_matched"] / combo_data["expected"] * 100)
            if combo_data["expected"] > 0
            else 0
        )
        combo_data["success_rate"] = success_rate
        result.append(combo_data)

    return sorted(result, key=lambda x: x["input_gens"])


def parse_args():
    parser = argparse.ArgumentParser(
        description="Serve HTML reports from CRS-multilang evaluation output"
    )
    parser.add_argument(
        "--root-eval-dir",
        type=Path,
        default="./eval_out_root",
        help=(
            "Root directory containing dated evaluation results (default:"
            " ./eval_out_root)"
        ),
    )
    parser.add_argument(
        "--multilang-root",
        type=Path,
        help="Path to CRS-multilang root directory (required for target info loading)",
    )
    parser.add_argument(
        "--default-date",
        default="latest",
        help="Default date to display (YYYY-MM-DD or 'latest', default: latest)",
    )
    parser.add_argument(
        "--port", type=int, default=43434, help="Port to serve on (default: 43434)"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to serve on (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--username", default="admin", help="Username for basic auth (default: admin)"
    )
    parser.add_argument(
        "--password",
        default="atlantis1!",
        help="Password for basic auth (required for authentication)",
    )
    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Disable authentication (not recommended)",
    )
    parser.add_argument(
        "--cache-duration",
        type=int,
        default=300,
        help="Cache duration in seconds (default: 300 = 5 minutes, 0 = no cache)",
    )
    parser.add_argument(
        "--cert-path",
        type=Path,
        default="./keys/fullchain.pem",
        help="Path to SSL certificate file (default: ./keys/fullchain.pem)",
    )
    parser.add_argument(
        "--key-path",
        type=Path,
        default="./keys/privkey.pem",
        help="Path to SSL private key file (default: ./keys/privkey.pem)",
    )
    return parser.parse_args()


def check_auth(username, password, required_username, required_password):
    """Check if username/password combination is valid"""
    return username == required_username and password == required_password


def authenticate():
    """Send 401 response that enables basic auth"""
    return Response(
        "Authentication required\nPlease provide valid credentials",
        401,
        {"WWW-Authenticate": 'Basic realm="CRS-multilang Reports"'},
    )


def requires_auth(username, password):
    """Decorator for routes that require authentication"""

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.authorization
            if not auth or not check_auth(
                auth.username, auth.password, username, password
            ):
                return authenticate()
            return f(*args, **kwargs)

        return decorated

    return decorator


def create_app(
    root_eval_dir: Path,
    cache_duration: int,
    multilang_root: Path = None,
    auth_username=None,
    auth_password=None,
):
    """Create Flask app to serve the reports"""
    # Configure Flask to use the web directory
    web_dir = Path(__file__).parent / "web"
    app = Flask(
        __name__,
        template_folder=str(web_dir / "templates"),
        static_folder=str(web_dir / "static"),
    )

    # Add custom template filters
    app.jinja_env.filters["format_tokens"] = format_tokens
    app.jinja_env.filters["format_cost"] = format_cost

    # Multi-date cache structure with thread safety
    _cache = {
        "available_dates": [],
        "last_dates_scan": 0,
        "dates": {},
        "cache_duration": cache_duration,
    }
    _cache_locks = {}  # Per-date locks to prevent concurrent cache updates
    _cache_lock = threading.Lock()  # Global lock for cache structure modifications

    def get_current_reports(date: str, force_refresh=False):
        """Get current reports with caching - now date-aware"""
        current_time = time.time()

        # Check cache for this specific date
        date_cache = _cache["dates"].get(date, {})

        # Determine cache refresh reasons
        cache_disabled = cache_duration == 0
        force_requested = force_refresh
        no_cached_reports = not date_cache.get("reports")
        cache_expired = current_time - date_cache.get("last_scan", 0) >= cache_duration

        should_refresh = (
            cache_disabled or force_requested or no_cached_reports or cache_expired
        )

        # Log cache decision
        if should_refresh:
            reasons = []
            if cache_disabled:
                reasons.append("cache_disabled")
            if force_requested:
                reasons.append("force_refresh")
            if no_cached_reports:
                reasons.append("no_cached_reports")
            if cache_expired:
                age = current_time - date_cache.get("last_scan", 0)
                reasons.append(f"cache_expired({age:.1f}s)")

            logger.info(
                f"[CACHE_REFRESH] Refreshing cache for date {date}:"
                f" {', '.join(reasons)}"
            )
        else:
            cache_age = current_time - date_cache.get("last_scan", 0)
            logger.debug(
                f"[CACHE_HIT] Using cached data for date {date} (age: {cache_age:.1f}s)"
            )

        # Use per-date locking to prevent concurrent cache updates for the same date
        with _cache_lock:
            if date not in _cache_locks:
                _cache_locks[date] = threading.Lock()
            date_lock = _cache_locks[date]

        with date_lock:
            # Re-check cache status inside the lock (double-checked locking pattern)
            current_time = time.time()  # Get fresh timestamp inside lock
            date_cache = _cache["dates"].get(date, {})

            # Recalculate cache refresh conditions inside the lock
            cache_disabled = cache_duration == 0
            force_requested = force_refresh
            no_cached_reports = not date_cache.get("reports")
            cache_expired = (
                current_time - date_cache.get("last_scan", 0) >= cache_duration
            )

            should_refresh_locked = (
                cache_disabled or force_requested or no_cached_reports or cache_expired
            )

            if should_refresh_locked:
                # Log cache decision inside lock
                reasons = []
                if cache_disabled:
                    reasons.append("cache_disabled")
                if force_requested:
                    reasons.append("force_refresh")
                if no_cached_reports:
                    reasons.append("no_cached_reports")
                if cache_expired:
                    age = current_time - date_cache.get("last_scan", 0)
                    reasons.append(f"cache_expired({age:.1f}s)")

                logger.info(
                    f"[CACHE_REFRESH] Refreshing cache for date {date}:"
                    f" {', '.join(reasons)}"
                )

                logger.info(f"Rescanning experiments for date: {date}")

                # Get date-specific eval_dir and zip_generator
                eval_dir = get_eval_dir_for_date(root_eval_dir, date)
                zip_generator = ZipGenerator(eval_dir)

                # Always check aggregate ZIP availability first (independent of experiments)
                aggregate_zips = zip_generator.check_aggregate_zip_availability()

                # Use discovery from experiments.py (handles experiment logging)
                reports = discover_all_experiments(eval_dir, multilang_root)
                if not reports:
                    reports = []

                # Check ZIP file availability for each report (read-only, no generation)
                for report in reports:
                    report.zip_files = zip_generator.check_zip_availability(
                        report.config_hash, report.target, report.harness_name
                    )

                # Update cache for this date
                if date not in _cache["dates"]:
                    _cache["dates"][date] = {}

                _cache["dates"][date].update(
                    {
                        "reports": reports,
                        "report_map": {
                            report.experiment_name: report for report in reports
                        },
                        "aggregate_zips": aggregate_zips,
                        "last_scan": current_time,
                    }
                )

                logger.info(
                    f"Cache updated with {len(reports)} experiments for date {date}"
                )
                return reports
            else:
                cache_age = current_time - date_cache.get("last_scan", 0)
                logger.debug(
                    f"[CACHE_HIT] Using cached data for date {date} (age:"
                    f" {cache_age:.1f}s)"
                )
                return date_cache.get("reports", [])

        logger.debug(f"Using cached reports for date {date}")
        return date_cache.get("reports", [])

    def get_available_dates(force_refresh=False):
        """Get available dates with caching"""
        current_time = time.time()

        if (
            force_refresh
            or not _cache["available_dates"]
            or current_time - _cache["last_dates_scan"]
            >= 60  # Refresh dates every minute
        ):
            _cache["available_dates"] = discover_available_dates(root_eval_dir)
            _cache["last_dates_scan"] = current_time

        return _cache["available_dates"]

    # Apply authentication decorator if credentials provided
    auth_decorator = (
        requires_auth(auth_username, auth_password)
        if auth_username and auth_password
        else lambda f: f
    )

    @app.route("/")
    @auth_decorator
    def index():
        # Redirect to latest date
        available_dates = get_available_dates()
        if not available_dates:
            return redirect("/")  # ("no_dates.html"), 404

        latest_date = available_dates[0]
        # Preserve query parameters
        query_string = request.query_string.decode()
        redirect_url = f"/date/{latest_date}/"
        if query_string:
            redirect_url += f"?{query_string}"
        return redirect(redirect_url)

    @app.route("/date/<date_str>/")
    @auth_decorator
    def index_with_date(date_str):
        # Validate and resolve date
        resolved_date = resolve_date(root_eval_dir, date_str)
        if not resolved_date:
            # available_dates = get_available_dates()
            return redirect("/")
            # return (
            #     render_template(
            #         "date_not_found.html",
            #         requested_date=date_str,
            #         available_dates=available_dates,
            #     ),
            #     404,
            # )

        # Get reports for this specific date
        current_reports = get_current_reports(resolved_date)

        # Build all mappings and combinations in a single pass
        hash_to_input_gens, input_gens_to_hash, unique_combinations = (
            build_experiment_mappings(current_reports)
        )

        # Always return all reports (no server-side filtering)
        sorted_reports = sorted(current_reports, key=lambda r: r.target)

        # Calculate aggregate statistics for all reports
        aggregate_stats = calculate_aggregate_stats(current_reports)
        input_gen_stats = calculate_input_gen_stats(current_reports, hash_to_input_gens)

        # Calculate aggregate finder statistics for the TOTAL row
        all_matched_pov_finders, all_unintended_pov_finders, all_uniafl_finders = (
            calculate_aggregate_finder_stats(input_gen_stats)
        )
        aggregate_stats["all_matched_pov_finders"] = all_matched_pov_finders
        aggregate_stats["all_unintended_pov_finders"] = all_unintended_pov_finders
        aggregate_stats["all_uniafl_finders"] = all_uniafl_finders

        # Get date-specific cache data
        date_cache = _cache["dates"].get(resolved_date, {})
        current_time = time.time()
        cache_data = {
            "last_scan": date_cache.get("last_scan", 0),
            "cache_duration": cache_duration,
            "current_time": current_time,
            "cache_disabled": cache_duration == 0,
        }

        # Get git info from the first report (all reports from same eval_dir have same git info)
        git_info = current_reports[0].git_info if current_reports else None

        # Prepare JSON-serializable reports data for JavaScript (LLM stats and finder stats)
        reports_for_js = []
        for report in sorted_reports:
            report_data = {
                "experiment_name": report.experiment_name,
                "litellm_stats": None,
                "finder_stats": None,
            }

            # Convert litellm_stats to dict if it exists
            if hasattr(report, "litellm_stats") and report.litellm_stats:
                report_data["litellm_stats"] = {
                    "total_spend": getattr(report.litellm_stats, "total_spend", 0.0),
                    "total_tokens": getattr(report.litellm_stats, "total_tokens", 0),
                    "total_prompt_tokens": getattr(
                        report.litellm_stats, "total_prompt_tokens", 0
                    ),
                    "total_completion_tokens": getattr(
                        report.litellm_stats, "total_completion_tokens", 0
                    ),
                    "total_cache_read_input_tokens": getattr(
                        report.litellm_stats, "total_cache_read_input_tokens", 0
                    ),
                    "total_cache_creation_input_tokens": getattr(
                        report.litellm_stats, "total_cache_creation_input_tokens", 0
                    ),
                    "total_successful_requests": getattr(
                        report.litellm_stats, "total_successful_requests", 0
                    ),
                    "total_failed_requests": getattr(
                        report.litellm_stats, "total_failed_requests", 0
                    ),
                    "total_api_requests": getattr(
                        report.litellm_stats, "total_api_requests", 0
                    ),
                }

            # Convert finder_stats to dict if it exists
            if hasattr(report, "corpus_analysis") and report.corpus_analysis:
                finder_stats_list = []
                for finder_stat in report.corpus_analysis.finder_stats:
                    finder_stats_list.append(
                        {
                            "finder_name": finder_stat.finder_name,
                            "pov_count": finder_stat.pov_count,
                            "matched_pov_count": finder_stat.matched_pov_count,
                            "unintended_pov_count": finder_stat.unintended_pov_count,
                            "others_corpus_count": finder_stat.others_corpus_count,
                            "uniafl_corpus_count": finder_stat.uniafl_corpus_count,
                            "total_seeds": finder_stat.total_seeds,
                        }
                    )
                report_data["finder_stats"] = finder_stats_list

            reports_for_js.append(report_data)

        return render_template(
            "index_table.html",
            current_date=resolved_date,
            available_dates=get_available_dates(),
            reports=sorted_reports,
            reports_for_js=reports_for_js,
            cache_data=cache_data,
            aggregate_zips=date_cache.get("aggregate_zips", {}),
            hash_to_input_gens=hash_to_input_gens,
            input_gens_to_hash=input_gens_to_hash,
            unique_combinations=unique_combinations,
            aggregate_stats=aggregate_stats,
            input_gen_stats=input_gen_stats,
            git_info=git_info,
        )

    # Date-aware routes
    @app.route("/date/<date_str>/reports/", defaults={"path": ""})
    @app.route("/date/<date_str>/reports/<path:path>")
    @auth_decorator
    def serve_reports_with_date(date_str, path):
        """Serve reports with catch-all routing - date-aware"""
        # Validate date
        resolved_date = resolve_date(root_eval_dir, date_str)
        if not resolved_date:
            return "Invalid date", 404

        logger.debug(f"Requested path: {path} for date: {resolved_date}")

        if not path:
            return "No experiment specified", 404

        # Get current report mapping using cache for this date
        get_current_reports(resolved_date)  # Ensure cache is updated
        date_cache = _cache["dates"].get(resolved_date, {})
        report_map = date_cache.get("report_map", {})

        # Split path into experiment name and file path
        path_parts = path.split("/")

        # Try to find the longest matching experiment name
        experiment_name = None
        file_path = None

        for i in range(len(path_parts), 0, -1):
            potential_experiment = "/".join(path_parts[:i])
            if potential_experiment in report_map:
                experiment_name = potential_experiment
                file_path = "/".join(path_parts[i:]) if i < len(path_parts) else ""
                break

        if not experiment_name:
            logger.warning(
                f"No matching experiment found for path: {path} on date:"
                f" {resolved_date}"
            )
            logger.debug(f"Available experiments: {list(report_map.keys())}")
            return "Experiment not found", 404

        report = report_map[experiment_name]
        logger.debug(f"Found experiment: {experiment_name}, file_path: {file_path}")

        # If no file path specified, redirect to linux/ directory
        if not file_path:
            return redirect(
                f"/date/{resolved_date}/reports/{quote(experiment_name)}/linux/"
            )

        # Handle linux/ directory specifically
        if file_path == "linux/":
            # linux_index = report.reports_path / "linux" / "index_table.html"
            linux_index = report.reports_path / "linux" / "index.html"
            if linux_index.exists():
                # return send_from_directory(report.reports_path / "linux", "index_table.html")
                return send_from_directory(report.reports_path / "linux", "index.html")
            else:
                return f"Report index not found for experiment: {experiment_name}", 404

        # Serve the requested file
        try:
            # First try from the reports base directory
            return send_from_directory(report.reports_path, file_path)
        except Exception as e:
            # If not found, try from the linux subdirectory
            try:
                return send_from_directory(report.reports_path / "linux", file_path)
            except Exception as e2:
                # Log available files for debugging
                logger.debug(f"Available files in {report.reports_path}:")
                if report.reports_path.exists():
                    for item in report.reports_path.rglob("*"):
                        if item.is_file():
                            logger.debug(f"  {item.relative_to(report.reports_path)}")
                logger.warning(
                    f"Failed to serve file {file_path} for {experiment_name}: {e}, {e2}"
                )
                return "File not found", 404

    @app.route("/date/<date_str>/download/zipfiles/<path:zip_path>")
    @auth_decorator
    def download_zip_with_date(date_str, zip_path):
        """Serve ZIP files from the date-specific zipfiles directory"""
        # Validate date
        resolved_date = resolve_date(root_eval_dir, date_str)
        if not resolved_date:
            return "Invalid date", 404

        eval_dir = get_eval_dir_for_date(root_eval_dir, resolved_date)
        zip_generator = ZipGenerator(eval_dir)

        try:
            return send_from_directory(
                zip_generator.zipfiles_dir, zip_path, as_attachment=True
            )
        except Exception as e:
            logger.warning(
                f"Failed to serve ZIP file {zip_path} for date {resolved_date}: {e}"
            )
            return "ZIP file not found", 404

    # Legacy routes (redirect to latest date)
    @app.route("/reports/", defaults={"path": ""})
    @app.route("/reports/<path:path>")
    @auth_decorator
    def serve_reports_legacy(path):
        """Legacy route - redirect to latest date"""
        available_dates = get_available_dates()
        if not available_dates:
            return "No evaluation data available", 404

        latest_date = available_dates[0]
        return redirect(f"/date/{latest_date}/reports/{path}")

    @app.route("/download/zipfiles/<path:zip_path>")
    @auth_decorator
    def download_zip_legacy(zip_path):
        """Legacy route - redirect to latest date"""
        available_dates = get_available_dates()
        if not available_dates:
            return "No evaluation data available", 404

        latest_date = available_dates[0]
        return redirect(f"/date/{latest_date}/download/zipfiles/{zip_path}")

    # Date-aware logs routes
    @app.route("/date/<date_str>/experiment/<config_hash>/<path:target>/<harness>/logs")
    @app.route(
        "/date/<date_str>/experiment/<config_hash>/<path:target>/<harness>/logs/<log_type>"
    )
    @auth_decorator
    def view_logs_with_date(
        date_str, config_hash, target, harness, log_type="docker_stdout"
    ):
        """Display logs for an experiment with tabbed interface - date-aware"""
        # Validate date
        resolved_date = resolve_date(root_eval_dir, date_str)
        if not resolved_date:
            return "Invalid date", 404

        # Validate log type
        valid_log_types = [
            "docker_stdout",
            "uniafl",
            "mlla",
            "metadata",
            "testlang",
            "reverser",
        ]
        if log_type not in valid_log_types:
            return f"Invalid log type. Valid types: {', '.join(valid_log_types)}", 400

        # Get date-specific eval_dir
        eval_dir = get_eval_dir_for_date(root_eval_dir, resolved_date)

        # Get current reports to access hash_to_input_gens mapping
        get_current_reports(resolved_date)  # Ensure cache is updated
        date_cache = _cache["dates"].get(resolved_date, {})

        # Build hash_to_input_gens mapping if not available in cache
        if "hash_to_input_gens" not in date_cache:
            current_reports = date_cache.get("reports", [])
            hash_to_input_gens, _, _ = build_experiment_mappings(current_reports)
            date_cache["hash_to_input_gens"] = hash_to_input_gens

        hash_to_input_gens = date_cache.get("hash_to_input_gens", {})
        input_generators = hash_to_input_gens.get(config_hash, "Unknown")

        # Define log file paths
        log_paths = {
            "docker_stdout": eval_dir / "stdout" / target / f"{config_hash}.txt",
            "uniafl": (
                eval_dir
                / "results"
                / config_hash
                / target
                / "workdir_result"
                / harness
                / "uniafl"
                / "workdir"
                / "log"
            ),
            "mlla": (
                eval_dir
                / "results"
                / config_hash
                / target
                / "workdir_result"
                / harness
                / "uniafl"
                / "workdir"
                / "mlla"
                / "workdir"
                / "log"
            ),
            "metadata": eval_dir / "metadata" / target / f"{config_hash}.json",
            "testlang": (
                eval_dir
                / "results"
                / config_hash
                / target
                / "workdir_result"
                / harness
                / "uniafl"
                / "input_gen_testlang_input_gen.log"
            ),
            "reverser": (
                eval_dir
                / "results"
                / config_hash
                / target
                / "workdir_result"
                / harness
                / "uniafl"
                / "workdir"
                / "harness-reverser"
                / "log.txt"
            ),
        }

        # Check which logs are available
        available_logs = {}
        for log_name, log_path in log_paths.items():
            available_logs[log_name] = log_path.exists()

        # Get the requested log content
        log_file = log_paths[log_type]
        content = ""
        error_message = None
        file_size = 0
        is_truncated = False
        MAX_DISPLAY_SIZE = 10 * 1024 * 1024  # 10MB

        if log_file.exists():
            try:
                file_size = log_file.stat().st_size
                is_truncated = file_size > MAX_DISPLAY_SIZE

                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    if is_truncated:
                        content = f.read(MAX_DISPLAY_SIZE)
                        content += (
                            f"\n\n[TRUNCATED - File is {format_file_size(file_size)},"
                            " showing first 10MB only]"
                        )
                    else:
                        content = f.read()
            except Exception as e:
                logger.warning(f"Failed to read log file {log_file}: {e}")
                error_message = f"Failed to read {log_type} log file"
        else:
            error_message = f"{log_type.replace('_', ' ').title()} log file not found"

        experiment_name = f"{config_hash}/{target}/{harness}"

        # Create relative path from eval_dir
        relative_log_file = (
            str(log_file.relative_to(eval_dir)) if log_file.exists() else "Not found"
        )

        # Calculate human-readable file size
        file_size_display = format_file_size(file_size)

        # Find matching experiment report to get LLM stats and timing data
        current_reports = date_cache.get("reports", [])
        matching_report = None
        for report in current_reports:
            if (
                report.config_hash == config_hash
                and report.target == target
                and report.harness_name == harness
            ):
                matching_report = report
                break

        # Extract LLM stats and timing data from matching report
        litellm_stats = None
        start_time = None
        end_time = None
        duration = None

        if matching_report:
            if (
                hasattr(matching_report, "litellm_stats")
                and matching_report.litellm_stats
            ):
                litellm_stats = matching_report.litellm_stats

            if hasattr(matching_report, "experiment_start_time"):
                start_time = matching_report.experiment_start_time

            if hasattr(matching_report, "experiment_end_time"):
                end_time = matching_report.experiment_end_time

            if hasattr(matching_report, "experiment_duration"):
                duration = matching_report.experiment_duration

        return render_template(
            "logs.html",
            current_date=resolved_date,
            content=content,
            error_message=error_message,
            experiment_name=experiment_name,
            config_hash=config_hash,
            target=target,
            harness=harness,
            log_type=log_type,
            available_logs=available_logs,
            log_file=relative_log_file,
            file_size=file_size or 0,
            file_size_display=file_size_display or "0B",
            input_generators=input_generators,
            is_truncated=is_truncated,
            litellm_stats=litellm_stats,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
        )

    # Legacy logs routes (redirect to latest date)
    @app.route("/stdout/<config_hash>/<path:target>/<harness>")
    @auth_decorator
    def view_stdout_legacy(config_hash, target, harness):
        """Legacy route - redirect to latest date"""
        available_dates = get_available_dates()
        if not available_dates:
            return "No evaluation data available", 404

        latest_date = available_dates[0]
        return redirect(
            f"/date/{latest_date}/experiment/{config_hash}/{target}/{harness}/logs/docker_stdout"
        )

    @app.route("/experiment/<config_hash>/<path:target>/<harness>/logs")
    @app.route("/experiment/<config_hash>/<path:target>/<harness>/logs/<log_type>")
    @auth_decorator
    def view_logs_legacy(config_hash, target, harness, log_type="docker_stdout"):
        """Legacy route - redirect to latest date"""
        available_dates = get_available_dates()
        if not available_dates:
            return "No evaluation data available", 404

        latest_date = available_dates[0]
        return redirect(
            f"/date/{latest_date}/experiment/{config_hash}/{target}/{harness}/logs/{log_type}"
        )

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(
            app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon"
        )

    return app


def main():
    args = parse_args()

    if not args.root_eval_dir.exists():
        logger.error(f"Root evaluation directory does not exist: {args.root_eval_dir}")
        return 1

    # Discover available dates
    available_dates = discover_available_dates(args.root_eval_dir)
    if not available_dates:
        logger.error("No valid evaluation dates found!")
        logger.info(
            f"Expected date directories (YYYY-MM-DD format) in: {args.root_eval_dir}"
        )
        return 1

    # Resolve default date
    default_date = resolve_date(args.root_eval_dir, args.default_date)
    if not default_date:
        logger.error(f"Invalid default date: {args.default_date}")
        logger.info(f"Available dates: {available_dates}")
        return 1

    logger.info(f"Available dates: {available_dates}")
    logger.info(f"Default date: {default_date}")

    # Test that we can discover experiments for the default date
    default_eval_dir = args.root_eval_dir / default_date
    reports = discover_experiments(default_eval_dir, args.multilang_root)

    if not reports:
        logger.warning(f"No experiment reports found for default date: {default_date}")
    else:
        logger.info(
            f"Found {len(reports)} experiments for default date: {default_date}"
        )

    # Setup authentication
    if not args.no_auth:
        if not args.password:
            logger.error(
                "Password is required for authentication. Use --password or --no-auth"
            )
            return 1
        logger.info(
            f"Authentication enabled - Username: {args.username}, Password:"
            f" {args.password}"
        )
    else:
        logger.warning("Authentication disabled - server is publicly accessible!")

    # Setup cache logging
    if args.cache_duration > 0:
        logger.info(
            f"Cache enabled - Duration: {args.cache_duration}s"
            f" ({args.cache_duration//60}m)"
        )
    else:
        logger.info("Cache disabled - Always fresh data")

    # Check certificate files availability
    certs_available = args.cert_path.exists() and args.key_path.exists()

    if not certs_available:
        logger.warning("SSL certificates not found:")
        logger.warning(
            f"  Certificate: {args.cert_path} (exists: {args.cert_path.exists()})"
        )
        logger.warning(
            f"  Private key: {args.key_path} (exists: {args.key_path.exists()})"
        )

        # Ask user for confirmation to continue with HTTP
        try:
            response = (
                input("Do you want to continue with HTTP mode? (y/n): ").strip().lower()
            )
            if response not in ["y", "yes"]:
                logger.info("Server startup cancelled by user")
                return 0
        except (KeyboardInterrupt, EOFError):
            logger.info("\nServer startup cancelled by user")
            return 0

        logger.warning("Continuing with HTTP mode")

    # Create Flask app with root directory
    app = create_app(
        args.root_eval_dir,
        args.cache_duration,
        args.multilang_root,
        args.username if not args.no_auth else None,
        args.password if not args.no_auth else None,
    )

    if certs_available:
        # HTTPS mode
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(str(args.cert_path), str(args.key_path))

        server_url = f"https://{args.host}:{args.port}"
        logger.success(f"Starting HTTPS server at {server_url}")
        logger.info(f"Serving experiments from {len(available_dates)} dates")
        logger.info(f"SSL Certificate: {args.cert_path}")
        logger.info(f"SSL Private Key: {args.key_path}")

        # Run the HTTPS server
        try:
            app.run(
                host=args.host, port=args.port, debug=False, ssl_context=ssl_context
            )
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
    else:
        # HTTP mode only
        server_url = f"http://{args.host}:{args.port}"
        logger.success(f"Starting HTTP server at {server_url}")
        logger.info(f"Serving experiments from {len(available_dates)} dates")
        logger.warning(
            "Running in HTTP mode - consider adding SSL certificates for security"
        )

        # Run the HTTP server
        try:
            app.run(host=args.host, port=args.port, debug=False)
        except KeyboardInterrupt:
            logger.info("Server stopped by user")

    return 0


if __name__ == "__main__":
    exit(main())
