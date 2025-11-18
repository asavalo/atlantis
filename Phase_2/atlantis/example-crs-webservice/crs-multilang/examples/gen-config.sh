#!/bin/bash

# Get the absolute paths for harness and work_dir
SCRIPT_DIR=$(dirname "$(realpath "$0")")
HARNESS_PATH="$SCRIPT_DIR/../uniafl/src/concolic/executor/symcc/symcc_binaries/test-harness"
WORK_DIR="$SCRIPT_DIR/../uniafl/src/concolic/executor/symcc/symcc_binaries/work_dir"
COV_DIR="$SCRIPT_DIR/../uniafl/src/concolic/executor/symcc/symcc_binaries/cov_dir"

# Input and output file paths
TEMPLATE_FILE="$SCRIPT_DIR/concolic.template.json"
OUTPUT_FILE="$SCRIPT_DIR/concolic.json"

# Ensure the examples directory exists
mkdir -p $WORK_DIR 

# Use jq to update the JSON
jq --arg harness "$HARNESS_PATH" \
   --arg work_dir "$WORK_DIR" \
   --arg cov_dir "$COV_DIR" \
   '.concolic.harness = $harness | .concolic.workdir = $work_dir | .cov_dir = $cov_dir | .workdir = $work_dir '\
   "$TEMPLATE_FILE" > "$OUTPUT_FILE"
