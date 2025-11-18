# SARIF Generator (Crash to SARIF)
- SARIF generator is a tool that generates SARIF files from crash logs.

## Usage

### Help

- You can check the help message for each command by using the help option (--help).

```sh
$ python scripts/generator.py --help

Usage: generator.py [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  compare-two-mode
  run-all
  run-llm
  run-one

# Run for just a single crash log
$ python scripts/generator.py run-one --help

Usage: generator.py run-one [OPTIONS] CRASH_LOG_PATH OUTPUT_FILE [[custom|ossfuzz]]

Options:
  --language [c|java]
  --llm_on BOOLEAN
  --validate BOOLEAN
  --patch_diff_path PATH
  --target_name TEXT
  --help                  Show this message and exit.

# Run for all crash logs in INDPUT_DIR
$ python scripts/generator.py run-all --help

Usage: generator.py run-all [OPTIONS] INPUT_DIR OUTPUT_DIR [[custom|ossfuzz]]

Options:
  --language [c|java]
  --llm_on BOOLEAN
  --validate BOOLEAN
  --help               Show this message and exit.

# Run LLM-based SARIF enhancement only
$ python scripts/generator.py run-llm --help

Usage: generator.py run-llm [OPTIONS] VULN_ID CRASH_LOG_PATH

Options:
  --patch_diff_path PATH
  --language [c|java]
  --help                  Show this message and exit.

# Compare location generate by two mode (custom | ossfuzz)
# See data/c/out/tests/compare_two_mode.out
$ python scripts/generator.py compare-two-mode --help
Usage: generator.py compare-two-mode [OPTIONS] INPUT_DIR

Options:
  --help  Show this message and exit.
```

### Example
```sh
# run one
$ python scripts/generator.py run-one ./data/java/in/crash_log/jenkins_JenkinsTwoCPVOne.log ./data/java/out/sarif/cp-jenkins_JenkinsTwoCPVOne.sarif  --patch_diff_path ./data/java/in/dev_patch/jenkins_JenkinsTwoCPVOne.diff --language java --llm_on True

# run all
$ python scripts/generator.py run-all ./data/c/in ./data/c/out custom

# run llm
python scripts/generator.py run-llm asc-nginx_cpv-1 ./data/c/in/crash_log/asc-nginx_cpv-1.log --patch_diff_path ./data/c/in/sound_patch/asc-nginx_cpv-1.diff --language c

# compare two modes
$ python scripts/generator.py compare-two-mode ./data/c/in
```