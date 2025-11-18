#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 7 ] && [ "$#" -ne 6 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <build-dir> <language> <tool> <mode> <TP|FP> <exp-name>"
    echo "language should be either 'c' or 'java' or 'cpp'"
    echo "tool should be either 'codeql', 'joern', 'introspector', 'svf' or 'sootup'"
    echo "mode should be either 'forward' or 'backward' or 'fuzzer-enhanced', 'line-reachableBy', 'func-reachableBy', 'callgraph', 'cha', 'rta', 'pta', 'ander'"
    echo "TP|FP should be either 'TP' or 'FP'"
    echo "exp-name is the name of the experiment"
    exit 1
fi

OSS_FUZZ_DIR=$1
BUILD_DIR=$2
LANGUAGE=$3
TOOL=${4:-codeql}
MODE=${5:-forward}
TP_FP=${6:-TP}
EXP_NAME=$7

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "java" ] && [ "$LANGUAGE" != "cpp" ]; then
    echo "Error: Language must be either 'c' or 'java' or 'cpp'"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"/codeql-db

ORIGINAL_LANGUAGE=$LANGUAGE
# Set the project directory based on language
if [ "$LANGUAGE" = "c" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/c"
    DOCKER_PATH="aixcc/c"
elif [ "$LANGUAGE" = "cpp" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/cpp"
    DOCKER_PATH="aixcc/cpp"
    LANGUAGE="c"
else
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/jvm"
    DOCKER_PATH="aixcc/jvm"
fi

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)
OUT_DIR="$ORIGINAL_DIR/data/$LANGUAGE/out"

EXP_NAME_OPTION=""
if [ -n "$EXP_NAME" ]; then
    EXP_NAME_OPTION="--exp-name $EXP_NAME"
fi

# Remove cache dir
# rm -rf ".cache"

for PROJECT in $PROJECTS; do
    # Kill all joern processes
    pgrep -f "sh /usr/local/bin/joern" | xargs -I {} pkill -P {}

    # Run CodeQL analysis
    echo "[+] Running reachability analysis for $PROJECT"

    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"

    HARNESS_NAMES=$(yq -r '.harness_files[].path' $PROJECT_CONFIG_FILE | xargs -n1 basename)

    COVERAGE_FILE="$OUT_DIR/fuzzing_coverage/$PROJECT-coverage.json"

    if [ "$TOOL" = "codeql" ]; then
        DB_DIR="$BUILD_DIR/codeql-db/$PROJECT"
        DB_OPTION="--db-path $DB_DIR"
    elif [ "$TOOL" = "joern" ]; then
        DB_DIR="$BUILD_DIR/joern-cpg/$PROJECT.cpg.bin"
        DB_OPTION="--db-path $DB_DIR"
    elif [ "$TOOL" = "introspector" ]; then
        DB_OPTION=""
    elif [ "$TOOL" = "sootup" ]; then
        DB_OPTION=""
    fi

    # TPs
    if [ "$TP_FP" = "TP" ]; then
        SARIF_DIR=$OUT_DIR/sarif
        SARIF_FILES=$(ls $OUT_DIR/sarif | grep "^${PROJECT}_")
    # FPs
    elif [ "$TP_FP" = "FP" ]; then
        SARIF_DIR=../benchmarks/refined/$LANGUAGE/$PROJECT
        SARIF_FILES=$(ls ../benchmarks/refined/$LANGUAGE/$PROJECT)
    else
        echo "Invalid TP_FP value: $TP_FP"
        exit 1
    fi

    mkdir -p $OUT_DIR/reachability-analysis/$PROJECT/$TP_FP

    for SARIF_FILE in $SARIF_FILES; do
        (set -x; python ./scripts/validator.py $PROJECT $LANGUAGE $PROJECT_CONFIG_FILE run-reachability-analysis $SARIF_DIR/$SARIF_FILE --mode $MODE $DB_OPTION --tool $TOOL $EXP_NAME_OPTION | tee $OUT_DIR/reachability-analysis/$PROJECT/$TP_FP/$SARIF_FILE-$TOOL-$MODE.log)
    done
done

# Parse the results
RES_DIR=$OUT_DIR/reachability-analysis/*/$TP_FP

FAILED_SARIF_FILES=()
SUCCESS_SARIF_FILES=()
UNKNOWN_SARIF_FILES=()

echo "[+] Processing reachability analysis results"
for FILE in $RES_DIR/*-$TOOL-$MODE.log; do
    echo "[+] Processing $FILE"

    # Extract the project name from the file name
    SARIF_NAME=$(basename $FILE .log)

    # Parse elpased time from string like "17.394712924957275 seconds"
    # ELAPSED_TIME=$(grep -oP '[0-9.]+ seconds' $FILE)
    # # if elapsed time empty, set it to RUN FAILED
    # if [ -z "$ELAPSED_TIME" ]; then
    #     ELAPSED_TIME="RUN FAILED (POSSIBLY DB CREATION FAILED)"
    # fi

    # SARIF_RES="${SARIF_NAME}          ${ELAPSED_TIME}"
    SARIF_RES="${SARIF_NAME}"

    # Extract the number of false positives
    # search "cannot be reachable" or "can be reachable"
    # count the number of lines that contain "cannot be reachable" or "can be reachable"
    if grep -q "Reachable" $FILE; then
        SUCCESS_SARIF_FILES+=("$SARIF_RES")
    elif grep -q "Unreachable" $FILE; then
        FAILED_SARIF_FILES+=("$SARIF_RES")
    else
        UNKNOWN_SARIF_FILES+=("$SARIF_RES")
    fi
done

# Create a stats file
STATS_FILE="$OUT_DIR/reachability_analysis_stats_${ORIGINAL_LANGUAGE}_${TOOL}_${MODE}_${TP_FP}.txt"
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
