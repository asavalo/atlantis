# CRS-multilang End-to-End Evaluation System

A comprehensive, dynamic evaluation system for running CRS-multilang fuzzing experiments across multiple targets and input generation combinations. This system provides automated experiment orchestration, resource management, result analysis, and web-based reporting for large-scale fuzzing campaigns.

## Overview

This evaluation system enables researchers to:
- Run fuzzing experiments across diverse targets (C, Java/JVM, C++)
- Test multiple input generation strategies (given_fuzzer, mlla, testlang, concolic, etc.)
- Manage system resources with dynamic CPU scheduling
- Track experiment progress with comprehensive monitoring
- Analyze results through an advanced web interface
- Ensure reproducibility with git metadata tracking

## System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   config.py     │    │   run_eval.py    │    │  run_server.py  │
│ Target configs  │───▶│ Experiment       │───▶│ Web interface   │
│ Input gen combos│    │ orchestration    │    │ & reporting     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   experiments.py │
                       │ Discovery &      │
                       │ analysis logic   │
                       └──────────────────┘
```

## Components

### Core Scripts

- **`run_eval.py`** - Main evaluation orchestrator with dynamic CPU scheduling, resource monitoring, and experiment lifecycle management
- **`run_server.py`** - Advanced web server for viewing experiment reports with multi-date support, authentication, and real-time caching
- **`run_prompts.py`** - Web-based AI prompt viewer for analyzing LLM interactions during fuzzing
- **`config.py`** - Centralized configuration for targets, harnesses, and input generation combinations

### Supporting Modules

- **`experiments.py`** - Core experiment discovery, analysis, and data processing logic
- **`generate_zips.py`** - Result packaging and ZIP file generation for easy distribution
- **`litellm_utils.py`** - LiteLLM integration utilities for AI-powered fuzzing capabilities
- **`utils.py`** - CPU management, job queuing, and system utilities
- **`analyze_docker_stat.py`** - Docker container resource usage analysis
- **`analyze_mpstat.py`** - CPU performance monitoring and analysis

### Installation Scripts

- **`install_deps.sh`** - Automated dependency installation and environment setup
- **`update_submodules.sh`** - Git submodule management for CRS-multilang components

## Installation & Setup

### Prerequisites

- **OSS-Fuzz Environment** - Required for target building and fuzzing infrastructure
- **Linux system** with Docker support (Ubuntu recommended)
- **Python 3.8+** with pyenv for environment management
- **Git** with submodule access to Team-Atlanta repositories
- **System tools**: `tmux`, `rsync`, `curl`, `wget`, `make`, `build-essential`, `clang-14`
- **Hardware**: 32+ CPU cores, 16GB+ RAM, 100GB+ disk space recommended

### Quick Setup

```bash
# Clone the repository
git clone git@github.com:Team-Atlanta/crs-multilang-e2e-eval.git
cd crs-multilang-e2e-eval

# Install dependencies and set up environment
./install_deps.sh

# Activate the Python environment
pyenv activate crs-e2e-experiments
```

The installation script automatically:
- Installs system dependencies (`tmux`, `rsync`, `pyenv`)
- Creates a dedicated pyenv environment
- Installs Python requirements
- Provides setup instructions for running experiments

### LiteLLM Configuration (Required)

Create a `.env.secret` file with your LiteLLM credentials:

```bash
# LiteLLM API configuration
LITELLM_MASTER_KEY=your_master_key_here
LITELLM_URL=your_litellm_endpoint_here
```

The system will prompt you if these credentials are missing and allow you to continue without them for testing purposes.

## Configuration

### Target Configuration

The system supports multiple target configurations in `config.py`:

```python
# Current active configuration
TARGETS_CONFIG = R3_TARGETS_FILTERED_CONFIG2

# Available configurations:
# - R2_TARGETS_CONFIG: Round 2 evaluation targets (7 targets)
# - R3_TARGETS_CONFIG: Round 3 evaluation targets (30+ targets)
# - R3_TARGETS_FILTERED_CONFIG: Filtered R3 targets (10 targets)
# - R3_TARGETS_FILTERED_CONFIG2: Minimal R3 targets (5 targets) - CURRENT
# - OUR_TARGETS_CONFIG: Custom research targets (50+ targets)
# - TARGETS_CONFIG_SANITIY: Basic sanity check targets (3 targets)
# - TARGET_CONFIG_STRESS: System stress testing targets (11 harnesses)
```

**Target Types Supported:**
- **C targets**: `aixcc/c/` - Native C programs with various harnesses
- **JVM targets**: `aixcc/jvm/` - Java applications with fuzzing harnesses
- **C++ targets**: `aixcc/cpp/` - C++ applications with specialized harnesses

**Delta/Diff Mode Testing:**
Many targets include delta variants (e.g., `r3-tika-delta-01`) for testing specific code changes or vulnerability patches.

**OSS-Fuzz Integration:**
Target configurations use OSS-Fuzz compatible project structures. Example OSS-Fuzz project names used in configurations:
- `aixcc/c/r3-sqlite3` → Uses OSS-Fuzz aixcc/c/sqlite3 project structure
- `aixcc/jvm/r3-apache-commons-compress` → Uses OSS-Fuzz aixcc/jvm/r3-apache-commons-compress project
- `aixcc/c/r3-curl` → Uses OSS-Fuzz aixcc/c/r3-curl project structure

*These are projects in our benchmark systems, but you can add your own projects into OSS-Fuzz compatible format and use this.*

### Input Generation Combinations

Configure which input generation strategies to test:

```python
INPUT_GEN_COMBINATIONS = [
    ["given_fuzzer", "concolic_input_gen", "testlang_input_gen", "dict_input_gen", "mlla"],
    # ["given_fuzzer"],
    # ["given_fuzzer", "mlla"],
    # ["given_fuzzer", "testlang_input_gen"],
]
```

### Resource Configuration

```python
NCPU_PER_RUN = 24                    # CPU cores per harness
EVAL_DURATION_SECONDS = 60 * 60 * 2  # 2 hours per experiment
PYENV_ENV_NAME = "crs-e2e-experiments"
```

**Note**: If a target has many harnesses, the total CPU requirement (`harnesses × NCPU_PER_RUN`) may exceed system capacity. The system automatically limits CPU allocation and logs warnings when this occurs.

## Running Experiments

### Basic Usage

```bash
# Activate environment
pyenv activate crs-e2e-experiments

# Run experiments with default settings
python run_eval.py

# Comprehensive example with dated output directory and full options
python run_eval.py --out-dir ~/eval_output/2025-06-24-r3-all --copy-workdir --multilang-root ~/CRS-multilang --start-other-services --cores-per-cp

# Additional examples
python run_eval.py --out-dir ~/my_eval_results --copy-workdir --start-other-services
python run_eval.py --start-core-idx 8 --cores-per-cp
```

### Command Line Options

```bash
python run_eval.py [OPTIONS]

Options:
  --multilang-root PATH     Path to CRS-multilang directory (default: ../../)
  --out-dir PATH           Output directory (default: ./eval_out)
  --start-core-idx INT     Starting core index (default: 0)
  --cores-per-cp           Use NCPU_PER_RUN cores per CP instead of per harness
  --start-other-services   Start additional services during evaluation
  --copy-workdir           Copy working directories to results
  --dont-cleanup-temps     Don't clean up temporary directories
  --skip-existing-images   Skip building if Docker images already exist
```

### Experiment Phases

1. **Configuration Setup** - Generate JSON configs for all target/input-gen combinations
2. **Metadata Collection** - Capture git repository state for reproducibility
3. **Status Analysis** - Check for completed/incomplete experiments
4. **Image Building** - Build CRS-multilang base and target Docker images
5. **Dynamic Job Scheduling** - Execute experiments with CPU resource management
6. **ZIP Generation** - Package results for distribution

## Directory Structure

```
eval_out/
├── configs/              # Generated configuration files
│   └── {target}/
│       └── {hash_str}.json
├── results/              # Experiment results
│   └── {hash_str}/
│       └── {target}/
│           ├── eval_result/        # Fuzzing results, PoVs, crash reports
│           │   ├── reports/        # HTML reports per harness
│           │   └── povs/          # Proof-of-vulnerability files
│           └── workdir_result/     # Working directories, intermediate files
├── stdout/               # Execution logs
│   └── {target}/
│       └── {hash_str}.txt
├── metadata/             # LiteLLM usage statistics
│   └── {target}/
│       └── {hash_str}.json
├── resource_usage/       # System resource monitoring
│   └── {target}/
│       └── {hash_str}.json
├── zipfiles/            # Generated ZIP packages
└── metadata.json        # Git repository metadata
```

### Hash String Definition

- **Hash String**: 16-character SHA256 hash of input generation combinations
- **Purpose**: Uniquely identifies experiment configurations
- **Example**: `f06f4ec5b4c8d7d6` represents `["given_fuzzer"]`
- **Usage**: Organizes configs, results, and logs across all components

## Web Interface

### Starting the Server

```bash
# Basic server (HTTP, default auth)
python run_server.py

# Custom configuration with specific eval directory and settings
python run_server.py --root-eval-dir ~/eval_output --port 12345 --cache-duration 1200 --multilang-root ~/CRS-multilang

# Additional examples
python run_server.py --root-eval-dir ~/eval_results --port 8080 --cache-duration 600

# HTTPS with SSL certificates
python run_server.py --cert-path ./keys/fullchain.pem --key-path ./keys/privkey.pem

# Disable authentication (local testing only)
python run_server.py --no-auth --cache-duration 0
```

### Server Command Line Options

```bash
python run_server.py [OPTIONS]

Options:
  --root-eval-dir PATH      Root directory containing dated evaluation results (default: ./eval_out_root)
  --multilang-root PATH     Path to CRS-multilang root directory (required for target info loading)
  --default-date DATE       Default date to display (YYYY-MM-DD or 'latest', default: latest)
  --port INT               Port to serve on (default: 43434)
  --host HOST              Host to serve on (default: 0.0.0.0)
  --username USER          Username for basic auth (default: admin)
  --password PASS          Password for basic auth (default: atlantis1!)
  --no-auth                Disable authentication (not recommended)
  --cache-duration INT     Cache duration in seconds (default: 300 = 5 minutes, 0 = no cache)
  --cert-path PATH         Path to SSL certificate file (default: ./keys/fullchain.pem)
  --key-path PATH          Path to SSL private key file (default: ./keys/privkey.pem)
```

### Key Features

- **Multi-Date Support**: Access results by date (`/date/2025-01-15/`) or latest (`/`)
- **Authentication**: Default `admin`/`atlantis1!`, customizable, or disable with `--no-auth`
- **HTTPS**: Auto-detects SSL certificates in `./keys/` directory
- **Dynamic Caching**: Real-time cache status with visual indicators and auto-refresh
- **SSL Setup**: Use `openssl` for self-signed certs or copy production certificates to `./keys/`

## Advanced Features

### Resource Monitoring

The system provides comprehensive resource monitoring:

- **CPU Usage**: Per-core utilization tracking with mpstat
- **Docker Stats**: Container resource consumption
- **Memory Usage**: System and per-experiment memory tracking
- **I/O Monitoring**: Disk and network usage statistics

### Git Metadata Tracking

Every experiment captures complete reproducibility information:

```json
{
  "experiment_start_time": "2025-01-15T10:30:00Z",
  "git_info": {
    "main_commit": "abc123...",
    "main_commit_date_utc": "2025-01-15T09:00:00Z",
    "submodules_with_dates": [
      {
        "path": "libs/uniafl",
        "commit": "def456",
        "date_utc": "2025-01-14T15:30:00Z"
      }
    ],
    "dirty": false
  }
}
```

### Dynamic CPU Scheduling

- **Slot Management**: Automatic CPU core allocation and deallocation
- **Target Collision Prevention**: Prevents multiple experiments on same target
- **Resource Limits**: Respects system CPU limits with warnings
- **Graceful Cleanup**: Signal handling for clean experiment termination

### LiteLLM Integration

- **User Management**: Automatic API user creation and cleanup
- **Usage Tracking**: Detailed token and cost monitoring
- **Request Statistics**: Success/failure rates and caching metrics
- **Multi-target Support**: Per-target API key management

## AI Prompt Viewer

Use `run_prompts.py` to analyze AI interactions during fuzzing:

```bash
# Start prompt viewer
python run_prompts.py --port 5050

# With SSL
python run_prompts.py --cert-path ./keys/fullchain.pem --key-path ./keys/privkey.pem
```

Access at `http://localhost:5050` to view and analyze AI prompts in a formatted interface.

## Result Analysis

### Experiment Reports

Each experiment generates comprehensive reports including:

- **PoV Discovery**: Proof-of-vulnerability files with crash analysis
- **Coverage Data**: Code coverage metrics and visualization
- **Corpus Analysis**: Seed generation and finder statistics
- **Performance Metrics**: Execution time and resource usage
- **LiteLLM Statistics**: AI interaction costs and token usage

### ZIP File Generation

Results are automatically packaged into ZIP files for easy distribution:

```bash
# Manual ZIP generation
python generate_zips.py --eval-dir ./eval_out
```

### Log Analysis

Multiple log types are available for each experiment:

- **Docker Stdout**: Main experiment execution logs
- **UniAFL Logs**: Fuzzer-specific execution details
- **MLLA Logs**: AI-powered input generation logs
- **Metadata**: LiteLLM usage and experiment metadata
- **TestLang Logs**: Test language generation logs
- **Reverser Logs**: Harness analysis and reversal logs

## Troubleshooting

### Common Issues

**Missing LiteLLM Credentials**
```bash
# Check .env.secret file exists and contains:
LITELLM_MASTER_KEY=your_key
LITELLM_URL=your_url
```

**Insufficient CPU Cores**
```bash
# System will warn and limit allocation automatically
# Reduce NCPU_PER_RUN or use --cores-per-cp flag
```

**Docker Build Failures**
```bash
# Skip existing images to save time
python run_eval.py --skip-existing-images

# Check Docker daemon is running
sudo systemctl status docker
```

**Web Server SSL Issues**
```bash
# Check certificate files exist
ls -la ./keys/
# Continue with HTTP if certificates missing
```

### Performance Optimization

- **CPU Allocation**: Use `--cores-per-cp` for targets with many harnesses
- **Disk Space**: Monitor `/tmp` usage during experiments
- **Memory Usage**: Consider system RAM when running multiple experiments
- **Network**: Ensure stable connection for LiteLLM API calls

## Development

### Adding New Targets

1. Add target configuration to `config.py`
2. Ensure target exists in CRS-multilang benchmarks
3. Test with sanity configuration first
4. Update documentation as needed

### Extending Analysis

- Modify `experiments.py` for new analysis features
- Update web templates in `web/templates/`
- Add new log types to server log viewing
- Extend ZIP generation for new result types

### Contributing

- Follow existing code style and patterns
- Add comprehensive logging for new features
- Update README.md for significant changes
- Test with multiple target configurations

## License

This project is part of the CRS-multilang evaluation framework developed by Team Atlanta.
