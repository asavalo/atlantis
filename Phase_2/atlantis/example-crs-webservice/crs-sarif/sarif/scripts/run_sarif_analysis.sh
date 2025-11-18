#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 3 ] && [ "$#" -ne 4 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <build-dir> <language>"
    echo "language should be either 'c', 'cpp' or 'java'"
    exit 1
fi

OSS_FUZZ_DIR=$1
BUILD_DIR=$2
LANGUAGE=$3

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "cpp" ] && [ "$LANGUAGE" != "java" ]; then
    echo "Error: Language must be either 'c', 'cpp' or 'java'"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"/codeql-db

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

if [ "$LANGUAGE" = "cpp" ]; then
    LANGUAGE="c"
fi

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)
OUT_DIR="../benchmarks/sarif_broadcast"

for PROJECT in $PROJECTS; do
    echo "[+] Running Sarif analysis for $PROJECT"
    
    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"

    # RES_PATH="$BUILD_DIR/sarif-db/$PROJECT/sarif-analysis.sarif"

    # # If sarif results already exists, skip it
    # if [ -f "$RES_PATH" ]; then
    #     echo "[+] Sarif analysis already exists for $PROJECT, skipping analysis"
    #     continue
    # fi

    # Run Sarif analysis
    echo "[+] Running Sarif analysis for $PROJECT"
    python ./scripts/validator.py $PROJECT $LANGUAGE $PROJECT_CONFIG_FILE get-sarif-analysis-result $OUT_DIR --build_dir $BUILD_DIR --codeql-db-path $BUILD_DIR/codeql-db/$PROJECT | tee $BUILD_DIR/codeql-db/sarif-analysis_$PROJECT.log
done