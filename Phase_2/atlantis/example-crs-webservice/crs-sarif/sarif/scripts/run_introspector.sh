#!/bin/bash

# set -x

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <sarif-package-dir> <language> <command>"
    echo "language should be either 'c', 'cpp' or 'java'"
    echo "command should be either 'reachability' or 'sink_analysis', 'update_sarif_package', 'reachability_from_sarif'"
    exit 1
fi

OSS_FUZZ_DIR=$1
SARIF_PACKAGE_DIR=$2
LANGUAGE=$3
COMMAND=$4

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "cpp" ] && [ "$LANGUAGE" != "java" ]; then
    echo "Error: Language must be either 'c', 'cpp' or 'java'"
    exit 1
fi

if [ "$COMMAND" != "reachability" ] && [ "$COMMAND" != "sink_analysis" ] && [ "$COMMAND" != "update_sarif_package" ] && [ "$COMMAND" != "reachability_from_sarif" ]; then
    echo "Error: Command must be either 'reachability' or 'sink_analysis', 'update_sarif_package', 'reachability_from_sarif'"
    exit 1
fi

# Set the project directory based on language
if [ "$LANGUAGE" = "c" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/c"
    DOCKER_PATH="aixcc/c"
elif [ "$LANGUAGE" = "cpp" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/cpp"
    DOCKER_PATH="aixcc/cpp"
else
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/jvm"
    DOCKER_PATH="aixcc/jvm"
fi

ORIGINAL_LANGUAGE=$LANGUAGE
# if [ "$LANGUAGE" = "cpp" ]; then
#     LANGUAGE="c"
# fi

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)
OUT_DIR="$ORIGINAL_DIR/data/$LANGUAGE/out"


for PROJECT in $PROJECTS; do
    echo "[+] Running Introspector for $PROJECT, command $COMMAND"
    
    OSS_FUZZ_OUT_DIR="$OSS_FUZZ_DIR/build/out/$DOCKER_PATH/$PROJECT"

    if [ "$COMMAND" = "reachability" ]; then
        OUTPUT="$OUT_DIR/reachability-analysis/$PROJECT-introspector-all_reachable_functions.json"
    elif [ "$COMMAND" = "sink_analysis" ]; then
        OUTPUT="$OUT_DIR/introspector/$PROJECT-$COMMAND.json"
    fi

    OUTPUT_IN_DOCKER="$OSS_FUZZ_OUT_DIR/reachable_functions_introspector.json"

    # If sarif results already exists, skip it
    if [ -f "$OUTPUT" ]; then
        echo "[+] Results already exist for $PROJECT, skipping analysis"
        continue
    fi

    # Check if the image exists. If not, build image using oss-fuzz scripts
    if docker images | grep -q "gcr.io/oss-fuzz/$DOCKER_PATH/$PROJECT"; then
        echo "[+] OSS-Fuzz image already exists for $PROJECT, skipping image build"
    else
        echo "[+] Building OSS-Fuzz image for $PROJECT"
        cd $OSS_FUZZ_DIR || exit 1
        python3 infra/helper.py build_image $DOCKER_PATH/$PROJECT --no-pull
        cd "$ORIGINAL_DIR" || exit 1
    fi

    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"
    
    # HARNESS_PATHS=$(yq -r '.harness_files[].path' $PROJECT_CONFIG_FILE | sed "s/\$PROJECT\///g")

    # Run Introspector
    echo "[+] Running Introspector for $PROJECT with command $COMMAND"
    if [ "$COMMAND" = "reachability" ]; then
        python ./scripts/introspector.py run-reachability-in-docker $PROJECT $LANGUAGE --sarif-package-dir $SARIF_PACKAGE_DIR --output $OUTPUT | tee $OUT_DIR/introspector/$PROJECT-$COMMAND.log
    elif [ "$COMMAND" = "sink_analysis" ]; then
        python ./scripts/introspector.py run-sink-analysis-in-docker $PROJECT $LANGUAGE --sarif-package-dir $SARIF_PACKAGE_DIR --output $OUTPUT | tee $OUT_DIR/introspector/$PROJECT-$COMMAND.log
    elif [ "$COMMAND" = "update_sarif_package" ]; then
        python ./scripts/introspector.py update-sarif-package $PROJECT $LANGUAGE --sarif-package-dir $SARIF_PACKAGE_DIR
    elif [ "$COMMAND" = "reachability_from_sarif" ]; then
        REACHABLE_FUNCTIONS_PATH="$OUT_DIR/reachability-analysis/$PROJECT-introspector-all_reachable_functions.json"
        SARIF_FILES=$(ls $OUT_DIR/sarif | grep "^${PROJECT}")

        for SARIF_FILE in $SARIF_FILES; do

            python ./scripts/introspector.py run-reachability-analysis-from-sarif $PROJECT $LANGUAGE --sarif-path $OUT_DIR/sarif/$SARIF_FILE --reachable-functions-path $REACHABLE_FUNCTIONS_PATH | tee $OUT_DIR/reachability-analysis/$SARIF_FILE-introspector.log
        done
    fi
done


if [ "$COMMAND" = "reachability_from_sarif" ]; then
# Parse the results
    RES_DIR=$OUT_DIR/reachability-analysis

    FAILED_SARIF_FILES=()
    SUCCESS_SARIF_FILES=()
    UNKNOWN_SARIF_FILES=()

    echo "[+] Processing reachability analysis results"
    for FILE in $RES_DIR/*-introspector.log; do
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
        if grep -q "Unreachable" $FILE; then
            FAILED_SARIF_FILES+=("$SARIF_RES")
        elif grep -q "Reachable" $FILE; then
            SUCCESS_SARIF_FILES+=("$SARIF_RES")
        else
            UNKNOWN_SARIF_FILES+=("$SARIF_RES")
        fi
    done

    # Create a stats file
    STATS_FILE="$OUT_DIR/reachability_analysis_stats_${ORIGINAL_LANGUAGE}_introspector.txt"
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
fi
