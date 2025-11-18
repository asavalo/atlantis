#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <out-dir> <language> <mode> <benchmark|projects>"
    echo "language should be either 'c', 'cpp'"
    echo "mode should be either 'ander', 'nander', 'sander', 'sfrander', 'steens', 'fspta', 'vfspta', 'type'"
    echo "benchmark|projects should be either 'benchmark' or 'projects'"
    exit 1
fi

OSS_FUZZ_DIR=$1
OUT_DIR=$2
LANGUAGE=$3
MODE=$4
TYPE=$5

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "cpp" ]; then
    echo "Error: Language must be either 'c' or 'cpp'"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$OUT_DIR"/SVF

if [ "$TYPE" = "benchmark" ]; then
    # Set the project directory based on language
    if [ "$LANGUAGE" = "c" ]; then
        PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/c"
        DOCKER_PATH="aixcc/c/"
    elif [ "$LANGUAGE" = "cpp" ]; then
        PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/cpp"
        DOCKER_PATH="aixcc/cpp/"
    else
        PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/jvm"
        DOCKER_PATH="aixcc/jvm/"
    fi

    # List all projects in the directory
    PROJECTS=$(ls $PROJECTS_DIR)
elif [ "$TYPE" = "projects" ]; then
    PROJECTS_DIR="$OSS_FUZZ_DIR/projects"
    DOCKER_PATH=""
    PROJECTS=$(cat "./scripts/${LANGUAGE}_compileable_projects.txt")
else
    echo "Invalid type: $TYPE"
    exit 1
fi
PROJECTS="mock-c"
echo "[+] PROJECTS: $PROJECTS"
for PROJECT in $PROJECTS; do
    echo "[+] Running SVF callgraph generation for $PROJECT"
    
    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"

    # Check if the image exists. If not, build image using oss-fuzz scripts
    # if docker images | grep -q "gcr.io/oss-fuzz/$DOCKER_PATH$PROJECT"; then
    # TODO: for debugging purposes, we use the local image
    if docker images | grep -q "aixcc-afc/$DOCKER_PATH$PROJECT"; then
        echo "[+] Image already exists for $PROJECT, skipping image build"
    else
        echo "[+] Building image for $PROJECT"
        cd $OSS_FUZZ_DIR || exit 1
        python3 infra/helper.py build_image $DOCKER_PATH$PROJECT --no-pull
        cd "$ORIGINAL_DIR" || exit 1
    fi

    mkdir -p "$OUT_DIR/$PROJECT/SVF"

    # Run SVF callgraph generation
    echo "[+] Running SVF callgraph generation for $PROJECT"
    # python ./scripts/svf.py mock-c c /home/user/work/oss-fuzz/projects/aixcc/c/mock-c/.aixcc/config.yaml run-svf-in-docker --mode ander | tee /home/user/out/mock-c/SVF/svf_run.log
    python ./scripts/svf.py $PROJECT $LANGUAGE $PROJECT_CONFIG_FILE run-svf-in-docker --mode $MODE | tee "$OUT_DIR/$PROJECT/SVF/svf_run.log"
done