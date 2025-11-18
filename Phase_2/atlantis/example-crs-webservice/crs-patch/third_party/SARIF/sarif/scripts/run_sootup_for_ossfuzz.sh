#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <out-dir> <mode> <pta-algorithm>"
    echo "mode should be either 'cha', 'rta', 'pta'"
    echo "pta-algorithm should be one of the following: 'insens', 'callsite_sensitive_1', 'callsite_sensitive_2', 'object_sensitive_1', 'object_sensitive_2', 'type_sensitive_1', 'type_sensitive_2', 'hybrid_object_sensitive_1', 'hybrid_object_sensitive_2', 'hybrid_type_sensitive_1', 'hybrid_type_sensitive_2', 'eagle_object_sensitive_1', 'eagle_object_sensitive_2', 'zipper_object_sensitive_1', 'zipper_object_sensitive_2', 'zipper_callsite_sensitive_1', 'zipper_callsite_sensitive_2'"
    exit 1
fi

OSS_FUZZ_DIR=$1
OUT_DIR=$2
MODE=$3
PTA=$4

PROJECTS_DIR="$OSS_FUZZ_DIR/projects"
PROJECTS=$(cat "./scripts/jvm_compileable_projects.txt")

for PROJECT in $PROJECTS; do
    echo "[+] Running Sootup for $PROJECT"
    
    PROJECT_CONFIG_FILE="$PROJECTS_DIR/$PROJECT/.aixcc/config.yaml"

    # Check if the image exists. If not, build image using oss-fuzz scripts
    if docker images | grep -q "gcr.io/oss-fuzz/$PROJECT"; then
        echo "[+] Image already exists for $PROJECT, skipping image build"
    else
        echo "[+] Building image for $PROJECT"
        cd $OSS_FUZZ_DIR || exit 1
        python3 infra/helper.py build_image $PROJECT --no-pull
        cd "$ORIGINAL_DIR" || exit 1
    fi

    # Build fuzzer
    echo "[+] Building fuzzer for $PROJECT"
    cd $OSS_FUZZ_DIR || exit 1
    python3 infra/helper.py build_fuzzers --sanitizer address $PROJECT
    cd "$ORIGINAL_DIR" || exit 1

    mkdir -p "$OUT_DIR/$PROJECT/Sootup"

    # Run Sootup callgraph generation
    echo "[+] Running Sootup callgraph generation for $PROJECT"
    (set -x; python ./scripts/validator.py $PROJECT java $PROJECT_CONFIG_FILE get-all-func-from-harness $OUT_DIR/$PROJECT/Sootup/reachable_methods.json --tool sootup --mode $MODE --pta-algorithm $PTA | tee "$OUT_DIR/$PROJECT/Sootup/sootup_run.log")
done