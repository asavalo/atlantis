#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <corpus-dir> <language>"
    echo "language should be either 'c' or 'java' or 'cpp'"
    exit 1
fi

OSS_FUZZ_DIR=$1
CORPUS_DIR=$2
LANGUAGE=$3

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "java" ] && [ "$LANGUAGE" != "cpp" ]; then
    echo "Error: Language must be either 'c' or 'java' or 'cpp'"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$ORIGINAL_DIR/data/$LANGUAGE/out/fuzzing_coverage"

# Set the project directory based on language
if [ "$LANGUAGE" = "c" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/c"
    DOCKER_PATH="aixcc/c"
elif [ "$LANGUAGE" = "cpp" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/cpp"
    DOCKER_PATH="aixcc/cpp"
elif [ "$LANGUAGE" = "java" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/jvm"
    DOCKER_PATH="aixcc/jvm"
fi

# List all projects in the directory
if [ "$LANGUAGE" = "c" ]; then
    # TODO: add more projects
    PROJECTS="mock-c"
elif [ "$LANGUAGE" = "cpp" ]; then
    # TODO: add more projects   
    PROJECTS="cp-user-opencv"
elif [ "$LANGUAGE" = "java" ]; then
    PROJECTS=$(ls $PROJECTS_DIR)
fi

OUT_DIR="$ORIGINAL_DIR/data/$LANGUAGE/out"

export PROJECTS_DIR
export LANGUAGE
export ORIGINAL_DIR
export CORPUS_DIR
export OUT_DIR

process_project() {
    local PROJECT=$1
    
    echo "[+] Running coverage replay for $PROJECT"

    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"
    HARNESS_NAMES=$(yq -r '.harness_files[].path' $PROJECT_CONFIG_FILE | xargs -n1 basename)

    python ./scripts/validator.py run-coverage-replay $PROJECT $HARNESS_NAMES $LANGUAGE --output $OUT_DIR/fuzzing_coverage/$PROJECT-coverage.json --corpus-dir $CORPUS_DIR
}
export -f process_project

NUM_CORES=$(nproc)
# PARALLEL_JOBS=$(($NUM_CORES / 2))
PARALLEL_JOBS=8
if [ $PARALLEL_JOBS -lt 1 ]; then
    PARALLEL_JOBS=1
fi

echo "[*] Running with $PARALLEL_JOBS parallel jobs"
echo $PROJECTS | tr ' ' '\n' | xargs -P $PARALLEL_JOBS -I{} bash -c 'process_project "{}"'
