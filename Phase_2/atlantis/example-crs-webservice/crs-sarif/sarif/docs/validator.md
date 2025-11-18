# SARIF Validator
- SARIF validator is a tool that validates broadcasted SARIF reports.
  
## Overview
1. Preprocessing
   1. Format validation
   2. Information extraction
2. Static Analysis
   1. Reachability analysis
   2. LLM-based validation
3. Dynamic Analysis
   1. Input corpus generation
   2. Direct fuzzing
4. Patch Generation


## Preprocessing

### Format validation
- [code](../sarif/validator/preprocess/format_validate.py)
### Information Extraction
- [code](../sarif/validator/preprocess/information_extraction.py)


## Static Analysis

### Reachability Analysis
- [docs](./reachability_analysis.md)
- [codeql code](../sarif/validator/reachability/codeql.py)
- [joern code](../sarif/validator/reachability/joern.py)

### LLM-based validation
TODO

## Dynamic analysis
TODO

## Patch Generation
TODO
