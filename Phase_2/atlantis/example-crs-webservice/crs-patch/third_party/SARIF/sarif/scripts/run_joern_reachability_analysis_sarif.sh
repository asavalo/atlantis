#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <build-dir> <language> <strategy>"
    echo "language should be either 'c' or 'java'"
    echo "strategy should be any of the following: 'line-reachableBy', 'func-reachableBy', 'callgraph', 'backward'"
    exit 1
fi

OSS_FUZZ_DIR=$1
BUILD_DIR=$2
LANGUAGE=$3
STRATEGY=$4

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "java" ]; then
    echo "Error: Language must be either 'c' or 'java'"
    exit 1
fi

# Validate strategy parameter
if [ "$STRATEGY" != "line-reachableBy" ] && [ "$STRATEGY" != "func-reachableBy" ] && [ "$STRATEGY" != "callgraph" ] && [ "$STRATEGY" != "backward" ]; then
    echo "Error: Strategy must be either 'line-reachableBy', 'func-reachableBy', 'callgraph', or 'backward'"
    exit 1
fi

# Set the project directory based on language
if [ "$LANGUAGE" = "c" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/c"
    DOCKER_PATH="aixcc/c"
else
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/jvm"
    DOCKER_PATH="aixcc/jvm"
fi

OUT_DIR="$ORIGINAL_DIR/data/$LANGUAGE/out"

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)

for PROJECT in $PROJECTS; do
    # Run Joern analysis
    echo "[+] Running Joern reachability analysis for $PROJECT"

    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"

    HARNESS_NAMES=$(yq -r '.harness_files[].path' $PROJECT_CONFIG_FILE | xargs -n1 basename)

    CPG_FILE="$BUILD_DIR/joern-cpg/$PROJECT.cpg.bin"

    SARIF_FILES=$(ls $OUT_DIR/sarif | grep "^${PROJECT}")

    for SARIF_FILE in $SARIF_FILES; do
        python ./scripts/validator.py joern-reachability-analysis-from-sarif $CPG_FILE $OUT_DIR/sarif/$SARIF_FILE $LANGUAGE $STRATEGY $HARNESS_NAMES | tee $OUT_DIR/reachability-analysis/joern_"$STRATEGY"_"$SARIF_FILE".log
    done
done

# Parse the results
RES_DIR=$OUT_DIR/reachability-analysis

FAILED_SARIF_FILES=()
SUCCESS_SARIF_FILES=()
UNKNOWN_SARIF_FILES=()
echo "[+] Processing reachability analysis results"
for FILE in $RES_DIR/joern_"$STRATEGY"_*.log; do
    echo "[+] Processing $FILE"

    # Extract the project name from the file name
    SARIF_NAME=$(basename $FILE .log)

    # Parse elpased time from string like "17.394712924957275 seconds"
    # ELAPSED_TIME=$(grep -oP '[0-9.]+ seconds' $FILE)
    # if elapsed time empty, set it to RUN FAILED
    # if [ -z "$ELAPSED_TIME" ]; then
    #     ELAPSED_TIME="RUN FAILED (POSSIBLY DB CREATION FAILED)"
    # fi

    # SARIF_RES="${SARIF_NAME}          ${ELAPSED_TIME}"
    SARIF_RES="${SARIF_NAME}"

    # Extract the number of false positives
    # search "Unreachable" or "Reachable"
    # count the number of lines that contain "Unreachable" or "Reachable"
    if [ "$STRATEGY" = "line-reachableBy" ] || [ "$STRATEGY" = "func-reachableBy" ]; then
        if grep -q "res1.*=.*0" $FILE; then
            FAILED_SARIF_FILES+=("$SARIF_RES")
        else
            SUCCESS_SARIF_FILES+=("$SARIF_RES")
        fi
    elif [ "$STRATEGY" = "callgraph" ] || [ "$STRATEGY" = "backward" ]; then
        if grep -q "Unreachable" $FILE; then
            FAILED_SARIF_FILES+=("$SARIF_RES")
        elif grep -q "Reachable" $FILE; then
            SUCCESS_SARIF_FILES+=("$SARIF_RES")
        else
            UNKNOWN_SARIF_FILES+=("$SARIF_RES")
        fi
    fi
done

# Create a stats file
STATS_FILE="$OUT_DIR/reachability_analysis_stats_joern_${STRATEGY}.txt"
# Print number of failed and success SARIF files to both console and file
{
echo "[+] Stats"
echo "Failed SARIF files: ${#FAILED_SARIF_FILES[@]}"
echo "Success SARIF files: ${#SUCCESS_SARIF_FILES[@]}"
echo "Unknown SARIF files: ${#UNKNOWN_SARIF_FILES[@]}"
echo

echo "[+] Failed SARIF files:"
for file in "${FAILED_SARIF_FILES[@]}"; do
    echo "$file"
done
echo

echo "[+] Success SARIF files:"
for file in "${SUCCESS_SARIF_FILES[@]}"; do
    echo "$file"
done
echo

echo "[+] Unknown SARIF files:"
for file in "${UNKNOWN_SARIF_FILES[@]}"; do
    echo "$file"
done
} | tee "$STATS_FILE"

echo "Statistics have been saved to $STATS_FILE"
