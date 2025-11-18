#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 3 ] && [ "$#" -ne 4 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <build-dir> <language> <qlpack>"
    echo "language should be either 'c', 'cpp' or 'java'"
    exit 1
fi

OSS_FUZZ_DIR=$1
BUILD_DIR=$2
LANGUAGE=$3
QLPACK=${4:-}

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
PROJECTS="mock-java"
for PROJECT in $PROJECTS; do
    echo "[+] Running CodeQL analysis for $PROJECT"
    
    # qlpack_name = qlpack.split("/")[-1].split(".")[0]
    if [ -n "$QLPACK" ]; then
        QLPACK_NAME=$(echo "$QLPACK" | rev | cut -d'/' -f 1 | cut -d'.' -f 1)
        RES_PATH="$BUILD_DIR/codeql-db/$PROJECT/codeql-analysis_$QLPACK_NAME.sarif"
    else
        RES_PATH="$BUILD_DIR/codeql-db/$PROJECT/codeql-analysis.sarif"
    fi

    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"

    # If sarif results already exists, skip it
    if [ -f "$RES_PATH" ]; then
        echo "[+] Sarif results already exist for $PROJECT, skipping analysis"
        continue
    fi

    # Check if the image exists. If not, build image using oss-fuzz scripts
    if docker images | grep -q "gcr.io/oss-fuzz/$DOCKER_PATH/$PROJECT"; then
        echo "[+] Image already exists for $PROJECT, skipping image build"
    else
        echo "[+] Building image for $PROJECT"
        cd $OSS_FUZZ_DIR || exit 1
        python3 infra/helper.py build_image $DOCKER_PATH/$PROJECT --no-pull
        cd "$ORIGINAL_DIR" || exit 1
    fi

    # Run CodeQL analysis
    echo "[+] Running CodeQL analysis for $PROJECT"
    if [ -n "$QLPACK" ]; then
        python ./scripts/codeql.py $PROJECT $LANGUAGE $PROJECT_CONFIG_FILE run-codeql-analysis-in-docker --build_dir $BUILD_DIR --qlpack $QLPACK | tee $BUILD_DIR/codeql-db/codeql-analysis_$PROJECT-$QLPACK_NAME.log
    else
        python ./scripts/codeql.py $PROJECT $LANGUAGE $PROJECT_CONFIG_FILE run-codeql-analysis-in-docker --build_dir $BUILD_DIR | tee $BUILD_DIR/codeql-db/codeql-analysis_$PROJECT.log
    fi
done