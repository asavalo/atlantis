# Atlantis-AFC

**Atlantis-AFC** is a comprehensive microservice-based Cyber Reasoning System (CRS) for C/C++ targets, built on a distributed Kafka-based producer-consumer architecture. This system provides advanced fuzzing capabilities through multiple specialized services working in concert to discover vulnerabilities to improve code robustness.

## Architecture Overview

The CRS orchestrates multiple microservices through Apache Kafka message queues, enabling scalable and distributed fuzzing workflows. The system is designed to handle complex C/C++ projects with sophisticated vulnerability discovery techniques.

### Workflow Architecture

```
Challenge Project (CP) Input
           │
           ▼
    ┌─────────────┐
    │  Bootstrap  │ ──── Initializes system, creates Kafka topics
    └─────────────┘
           │
           ├──────────────────┬──────────────────┐
           ▼                  ▼                  ▼
    ┌─────────────┐    ┌─────────────┐   ┌─────────────┐
    │ Controller  │    │    OSV      │   │  Harness    │
    │  Service    │    │  Analyzer   │   │Reachability │
    └─────────────┘    └─────────────┘   └─────────────┘
           │                  │                  │
           ▼                  │                  │
    ┌─────────────┐           │                  │
    │   Harness   │           │                  │
    │   Builder   │           │                  │
    └─────────────┘           │                  │
           │                  │                  │
           └──────────────────┼──────────────────┘
                              ▼
                       ┌─────────────┐
                       │ Controller  │ ──── Starts fuzzing phase
                       │  Service    │
                       └─────────────┘
                              │
           ┌──────────────────┼──────────────────┬─────────────────┐
           ▼                  ▼                  ▼                 ▼
    ┌─────────────┐    ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
    │   Fuzzer    │◄── │  DeepGen    │   │  Directed   │   │   Custom    │
    │  Manager    │    │  Service    │   │  Fuzzing    │   │   Fuzzer    │
    └─────────────┘    └─────────────┘   └─────────────┘   └─────────────┘
           ▲ │                │                  │                 │
           │ └────────────────┴──────────────────┼─────────────────┘
           │                          ┌──────────┴───────────┐
           │                          ▼                      ▼ 
           │                   ┌─────────────┐        ┌─────────────┐
           │                   │    Crash    │        │    Seeds    │
           │                   │  Collector  │        │  Collector  │
           │                   └─────────────┘        └─────────────┘
           │                          │                      │
           │                          │                      │
           │                          │  ┌─────────────┐     │ 
           │                          └─►│    Seed     │◄────┘
           │                             │ Ensembler   │
           │                             └─────────────┘
           │                                    │
           └────────────────────────────────────┤
                                                │
                                                ▼
                                         Submit Crashes
```

## Setup

1. Clone this repository with submodules and Git LFS.
2. Set any desired environment variables, [described below](#environment-variables).
    - In particular, the CRS needs the `oss_fuzz` repository and the CP repository to analyze. If you want it to use specific copies of those (e.g., from the Competition API), set `CRS_OSS_FUZZ_PATH` and/or `CRS_TARGET_SRC_PATH`. Otherwise, the CRS will attempt to clone those itself using [the Team-Atlanta fork of the oss-fuzz repo](https://github.com/Team-Atlanta/oss-fuzz), which is **only suitable for development**.
3. Finally, run `docker-run.py` to launch the CRS:

```
usage: docker-run.py [-h] [--tag [TAG]] [--registry [REGISTRY]] [--profile [{development,evaluation,postmortem}]] [{run,clean,build,push}] [target] [harness] [sanitizer]

positional arguments:
  {run,clean,build,push}
  target
  harness
  sanitizer

options:
  -h, --help            show this help message and exit
  --tag [TAG]
  --registry [REGISTRY]
  --profile [{development,evaluation,postmortem}], -p [{development,evaluation,postmortem}]
```

The "target CP name" is the subdirectory of `<oss_fuzz>/projects`. For example, to analyze `<oss_fuzz>/projects/aixcc/cpp/example-libpng`, use `aixcc/cpp/example-libpng`.

`docker-run.py` builds the necessary CRS Docker images and launches them.


## Environment Variables

`docker-run.py` recognizes these environment variables:

- `LITELLM_KEY`: the litellm provisiond API key
- `AIXCC_LITELLM_HOSTNAME`: the litellm proxy address
- `NODE_NUM` (default: 4): the number of nodes the CRS should simulate
- `NODE_CPU_CORES` (default: `ncpu / NODE_NUM`): the number of CPU cores allocated per node
- `CRS_OSS_FUZZ_PATH` (default: `<this repo dir>/oss_fuzz`): the path to the `oss_fuzz` repository. `docker-run.py` will clone it there [from here](https://github.com/Team-Atlanta/oss-fuzz) if it doesn't exist, but it's otherwise treated as read-only.
- `CRS_TARGET_SRC_PATH` (default: `<this repo dir>/cp_root/<target CP name with "/"s replaced with "_"s>`): the path to the CP repository directory. `docker-run.py` will clone it there from the URL listed in the project's `project.yaml` if it doesn't exist, but it's otherwise treated as read-only.
- `CRS_SCRATCH_SPACE` (default: `<this repo dir>/crs_scratch`): a directory the CRS can use as a shared scratch space between its various Docker containers
- `SHARED_CRS_SPACE` (default: `<this repo dir>/shared-crs-fs`): a directory the CRS can use to shared files among different node (hardware) and different CRS, it will be using NFS in the remote environment
- `CRS_BUILD_CP_IMAGE` (default: `true`): whether the CRS should attempt to build the CP's Docker image. To instead just assume that it's already been built, set this to `false` or `0`.

If you want to set environment variables *inside* the CRS's Docker container (shouldn't be necessary in most cases), create an `.env.user` file with one per line, in the format `KEY=VALUE`.

Common environment variables to use in `.env.user` are debugging overrides
- `EPOCH_DURATION`: epoch length in seconds
- `VERBOSE_FUZZER`: blast fuzzer logs
- `OVERRIDE_HARNESSES`: comma-separated list of harness names to run
- `OVERRIDE_FUZZER`: name of fuzzing engine to use, potential values are libafl, afl, libfuzzer

## Core CRS Services

### Bootstrap
- (Launches the system, is not techically a service)
- **Purpose**: System initialization and setup orchestration
- **Responsibilities**: 
  - Creates Kafka topics and initializes message queues
  - Configures shared volumes and directory structures
  - Manages initial system state preparation
- **Location**: `bootstrap/`

### Controller Service 
- **Purpose**: Central coordination and task scheduling
- **Responsibilities**:
  - Orchestrates workflow between all microservices
  - Manages resource allocation and core distribution
  - Coordinates fuzzing epochs and task prioritization
- **Key Components**: `task_scheduler.py`, `core_allocator.py`
- **Location**: `microservices/controller/`

### Harness Builder Service
- **Purpose**: Test harness compilation for fuzzing targets
- **Responsibilities**:
  - Compile binaries of fuzz harnesses
  - Support multiple fuzzer types
  - Provide multiple instrumentation modes
- **Key Components**: `builder_impl.py`, `config_gen/`
- **Location**: `microservices/harness_builder/`

### Fuzzer Manager Service
- **Purpose**: Manages and coordinates different fuzzing engines
- **Responsibilities**:
  - Launches and monitors fuzzing sessions (LibFuzzer, LibAFL, AFL++)
  - Handles fuzzer process lifecycle management
  - Collects and reports fuzzing statistics
- **Key Components**: `fuzzer_session.py`, `run_fuzzer`
- **Location**: `microservices/fuzzer_manager/`

### Harness Reachability Service
- **Purpose**: Static and dynamic reachability analysis
- **Responsibilities**:
  - Performs code reachability analysis for targets
  - Identifies potential entry points for fuzzing
  - Conducts differential analysis between code versions
- **Key Components**: `diff_analysis/`
- **Location**: `microservices/harness_reachability/`

### OSV Analyzer Service
- **Purpose**: Open Source Vulnerability database analysis and corpus generation
- **Responsibilities**:
  - Analyzes project to determine application domain
  - Searches OSV database for relevant fuzzing corpuses
  - Selects targeted test inputs based on project type
- **Key Components**: `analyze.py`
- **Location**: `microservices/osv_analyzer/`

### Seeds Collector Service
- **Purpose**: Fuzzing seed corpus management
- **Responsibilities**:
  - Monitors corpuses from all active fuzzers
  - Sends and receives seeds to/from Seed Ensembler Service
  - Sends and receives seeds to/from CRS-Multilang seed share
- **Location**: `microservices/seeds_collector/`

### Crash Collector Service
- **Purpose**: Crash triage and vulnerability analysis
- **Responsibilities**:
  - Collects and processes crashes from all fuzzing engines
- **Location**: `microservices/crash_collector/`

### Seed Ensembler Service
- **Purpose**: Test seeds and redistributes them appropriately
- **Responsibilities**:
  - Aggregates seeds from multiple sources
  - Tests seeds for crashes, timeouts, and code coverage
  - Sends crashing seeds to VAPI, and coverage-increasing seeds to fuzzers
- **Location**: `microservices/seed_ensembler/`

## LLM-Enhanced Services

### DeepGen Service
- **Purpose**: LLM-powered intelligent test case generation
- **Responsibilities**:
  - Leverages large language models for context-aware fuzzing
  - Generates semantically meaningful test inputs
  - Provides adaptive mutation strategies based on code analysis
- **Key Components**: `dealer.py`, `worker.py`, `task_models.py`
- **Location**: `microservices/deepgen_service/`

### C LLM Service (Mutator)
- **Purpose**: LLM-based mutation engine for C/C++ code
- **Responsibilities**:
  - Applies intelligent mutations using language models
  - Observes corpus evolution and adapts mutation strategies
  - Provides context-aware code transformation
- **Key Components**: `mutator.py`, `corpus_observer.py`
- **Location**: `microservices/c_llm/`

## Specialized Fuzzing Services

### Directed Fuzzing Service
- **Purpose**: Target-directed fuzzing with static analysis guidance
- **Responsibilities**:
  - Implements directed greybox fuzzing techniques
  - Uses LLVM bitcode analysis for target guidance
  - Integrates with AFL++ for directed campaign execution
- **Key Components**: Built on AFL++ with custom modifications
- **Location**: `microservices/directed_fuzzing/`

### Custom Fuzzer Service
- **Purpose**: Domain-specific and grammar-based fuzzing
- **Responsibilities**:
  - Supports specialized fuzzing engines (grammar, DBMS, WebAssembly)
  - Integrates custom fuzzing logic for specific domains
  - Provides extensible framework for custom fuzzer integration
- **Key Components**: `userspace-custom-fuzzers/`
- **Location**: `microservices/custom_fuzzer/`

## Supporting Services

### Coverage Service
- **Purpose**: Code coverage analysis and reporting
- **Responsibilities**:
  - Collects coverage information from instrumented binaries
  - Provides real-time coverage feedback to fuzzing engines
  - Generates coverage reports and visualizations
- **Location**: `microservices/coverage_service/`

## Workflow Overview

The CRS follows a structured workflow from challenge project input to final results:

1. **Project Ingestion**: Bootstrap receives the Challenge Project (CP) and initializes the system environment, creating necessary Kafka topics and shared directories

2. **Task Orchestration**: Controller Service takes over workflow management, analyzing the CP structure and dispatching appropriate tasks to specialized services

3. **Analysis & Preparation**: Three services work in parallel:
   - **Harness Builder**: Generates fuzz harnesses from C/C++ source code
   - **OSV Analyzer**: Searches vulnerability databases for relevant patterns and creates targeted corpus
   - **Harness Reachability**: Performs static analysis to identify fuzzing entry points

4. **Fuzzing Coordination**: Controller Service aggregates analysis results and initiates the fuzzing phase by dispatching work to multiple fuzzing engines

5. **Parallel Fuzzing**: Four fuzzing services operate simultaneously:
   - **Fuzzer Manager**: Coordinates traditional fuzzers (AFL++, LibFuzzer, LibAFL)
   - **DeepGen Service**: Provides LLM-powered intelligent test case generation
   - **Directed Fuzzing**: Performs target-directed fuzzing using static analysis guidance
   - **Custom Fuzzer**: Runs domain-specific and grammar-based fuzzers

6. **Continuous Monitoring**: Collection services monitor fuzzing directories and shared file systems:
   - **Seeds Collector**: Gathers and optimizes fuzzing corpus from all active fuzzers
   - **Crash Collector**: Detects, triages, and analyzes crashes as they occur

7. **Testcase Submission**: Seed Ensembler combines seeds from various sources, performs corpus optimization, and prepares final results for output

## Message Flow

The system uses Kafka topics for inter-service communication:
- **Task Distribution**: Controller publishes tasks to specialized topic queues based on workflow phase
- **Status Updates**: Services report completion status and results back through dedicated response topics  
- **File System Monitoring**: Collectors monitor shared directories and communicate findings via status topics
- **Resource Coordination**: Real-time coordination messages ensure proper resource allocation and prevent conflicts
- **Telemetry**: Performance metrics, logs, and system health data collected via dedicated telemetry topics


# Licensing

As CRS-Userspace depends on some components distributed under the GNU GPL v3 license, it is licensed under GNU GPL v3 as well.

Some data -- primarily fuzzing corpora and lists of filenames and function names -- has been aggregated from projects participating in the OSS-Fuzz project. [All of these projects are distributed under open-source licenses](https://google.github.io/oss-fuzz/faq/#my-project-is-not-open-source-can-i-use-oss-fuzz), but some may be under the GNU GPL v2, which is not compatible with v3. Since we only use some data files collected from these projects, not executable code, we believe our usage counts as "aggregation" and is exempt from the GNU GPL v2's copyleft requirement.
