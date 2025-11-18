## Overview

Running Query-based Static Application Security Testing (SAST) for generating SARIF validation benchmarks.
SAST tools are selected based on the availability and two recent papers:
1. Li, Kaixuan, et al. "Comparison and evaluation on static application security testing (sast) tools for java." Proceedings of the 31st ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering. 2023.
2. Li, Zongjie, et al. "Evaluating c/c++ vulnerability detectability of query-based static application security testing tools." IEEE Transactions on Dependable and Secure Computing 21.5 (2024): 4600-4618.

## Available SAST
- `semgrep` (DONE)
- `snyk` (DONE)
- `sonarqube` (TODO)
- `joern` (TODO)
- `codeql` (DONE, `codeql analyze` can be executed in the sarif package)

## Prerequisites
- `semgrep`, `snyk`, `sonarqube` all provide community versions, but the paid versions offer better features and queries.
- All three services provide free trials, so there is no problem for benchmark generation.
- Therefore, you need to access each site to issue a token and save it in the .env file.

## Usage
```
./build_and_run_all_docker.sh <OSS_FUZZ_DIR> <c|cpp|java>
```

## TODO
- [] joern-scan does not support output in sarif format. The results need to be parsed.
- [] sonarqube requires specifying build commands. Need to set build commands for each project using ./build.sh or compile commands, etc.