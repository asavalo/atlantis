# Reachability Analysis
- Reachability analysis is a process of determining whether a target function can be reached from a given harness file using in the validator.

# CodeQL
- Reachability analysis using CodeQL is performed through a simple call graph analysis.
- It primarily checks whether there is a call graph flow connecting (harness files -> target_file:target_function).
  - [C query](../sarif/codeql/ql/c/forward_reachability_many_to_one.jinja2)
  - [Java query](../sarif/codeql/ql/java/forward_reachability_many_to_one.jinja2)

## Usage
```bash
# Run just one SARIF report
# python ./scripts/validator.py run-reachability-analysis-from-sarif DB_PTH SARIF_PATH {c|java} [HARNESS_NAMES] 
python scripts/validator.py run-reachability-analysis-from-sarif ./build/codeql-db/asc-nginx ./data/c/out/sarif/asc-nginx_cpv-1.sarif c pov_harness.cc

# Run for all crash-to-SARIF results (TPs)
./scripts/run_forward_reachability_analysis_sarif.sh /home/user/work/team-atlanta/oss-fuzz ./build c
./scripts/run_forward_reachability_analysis_sarif.sh /home/user/work/team-atlanta/oss-fuzz ./build java