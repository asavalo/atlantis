# vuli

vuli is a tool to generate PoVs including harness_id, sanitizer_id and blobs.
vuli uses llm, static taint analysis to infer values that trigger vulnerabilities.

## prerequisite

### Poetry

`vuli` uses `poetry` for managing dependencies and packaging. Please follow below instructions before you start to use `vuli`.

Install `poetry`: `curl -sSL https://install.python-poetry.org | python -`
Install dependencies: `poetry install`

## usage

You can run tool using below command.
`LITELLM_KEY=... poetry run python -m vuli.main`

Detail usage of `vuli` will be updated later.

### joern

joern should be available. Please install joern and give joern path to the tool with option --joern_dir

### cp metadata file

cp metadata file should be available. Please install cp and build them. And then give the path to the tool with opeion --cp_meta

### gpt4-o

gpt4-o should be avilable. Please specify your api key as environment variable 'LITELLM_KEY'

## Contribution

Before put your commit, please do below things first, and fix all errors or warnings from them.

1. Unit Test: `poetry run pytest -s tests`
1. Lint: `poetry run black .`

## test

You should build sample project first before running unit test. You can install it using below command.
`tests/sample/prepare.sh`

Now, you can run test using below command.
`poetry run pytest -s tests`
