#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <language>"
    echo "language should be either 'c' or 'java'"
    exit 1
fi

OSS_FUZZ_DIR=$1
LANGUAGE=$2

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "java" ]; then
    echo "Error: Language must be either 'c' or 'java'"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$ORIGINAL_DIR/data/$LANGUAGE/out/essential_sarif"

# Set the project directory based on language
if [ "$LANGUAGE" = "c" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/c"
    DOCKER_PATH="aixcc/c"
else
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/jvm"
    DOCKER_PATH="aixcc/jvm"
fi

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)

for PROJECT in $PROJECTS; do
    # Run CodeQL analysis
    echo "[+] Running info extraction for $PROJECT"

    OUT_DIR="$ORIGINAL_DIR/data/$LANGUAGE/out"
    DEBUG_DIR="$ORIGINAL_DIR/data/$LANGUAGE/out/essential_sarif"
    SARIF_FILES=$(ls $OUT_DIR/sarif | grep "^${PROJECT}")

    for SARIF_FILE in $SARIF_FILES; do
        python ./scripts/validator.py extract-essential-info-from-sarif $OUT_DIR/sarif/$SARIF_FILE $DEBUG_DIR/$SARIF_FILE-essential_info.json
    done
done
