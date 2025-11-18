#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <language>"
    echo "language should be either 'c', 'cpp' or 'java'"
    exit 1
fi

OSS_FUZZ_DIR=$1
LANGUAGE=$2

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "cpp" ] && [ "$LANGUAGE" != "java" ]; then
    echo "Error: Language must be either 'c', 'cpp' or 'java'"
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


BUILD_ARGS=""
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ "$line" =~ ^# ]] || [[ -z "$line" ]] && continue
  
  [[ "$line" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || continue
  
  var_name="${line%%=*}"
  BUILD_ARGS="$BUILD_ARGS --build-arg $var_name=${!var_name:-${line#*=}}"
done < .env

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)
DOCKER_FILE_NAME="Dockerfile"

for PROJECT in $PROJECTS; do
    echo "[+] Building SAST docker image for $PROJECT"

    OSS_FUZZ_OUT_DIR="$OSS_FUZZ_DIR/build/out/$DOCKER_PATH/$PROJECT"

    BASE_IMAGE_NAME="gcr.io/oss-fuzz/$DOCKER_PATH/$PROJECT"
    BUILD_ARGS="$BUILD_ARGS --build-arg BASE_IMAGE_NAME=$BASE_IMAGE_NAME"
    DOCKER_IMAGE_NAME="$BASE_IMAGE_NAME-sast"
    
    # Check if the image exists. If not, build image using oss-fuzz scripts
    if docker images | grep -q "$DOCKER_IMAGE_NAME"; then
        echo "[+] Image already exists for $PROJECT, skipping image build"
    else
        echo "[+] Building image for $PROJECT static analysis"
        # Format string to replace the base image name with the new image name
        # sed "s/BASE_IMAGE_NAME/$BASE_IMAGE_NAME/" $DOCKER_FILE_NAME
        docker build $BUILD_ARGS -t $DOCKER_IMAGE_NAME -f $DOCKER_FILE_NAME .
    fi

    VOLUME_ARGS="-v $OSS_FUZZ_OUT_DIR:/out"

    # Run the docker image
    echo "[+] Running docker image for $PROJECT"

    # Run semgrep
    if [ -f "$OSS_FUZZ_OUT_DIR/semgrep.sarif" ]; then
        echo "[+] Semgrep results already exist for $PROJECT, skipping"
    else
        echo "[+] Running semgrep for $PROJECT"
        docker run -it $VOLUME_ARGS $DOCKER_IMAGE_NAME run_semgrep.sh
    fi

    # Run snyk
    if [ -f "$OSS_FUZZ_OUT_DIR/snyk.sarif" ]; then
        echo "[+] Snyk results already exist for $PROJECT, skipping"
    else
        echo "[+] Running snyk for $PROJECT"
        docker run -it $VOLUME_ARGS $DOCKER_IMAGE_NAME run_snyk.sh
    fi

    # # Run joern
    # if [ -f "$OSS_FUZZ_OUT_DIR/joern.sarif" ]; then
    #     echo "[+] Joern results already exist for $PROJECT, skipping"
    # else
    #     echo "[+] Running joern for $PROJECT"
    #     docker run -it $VOLUME_ARGS $DOCKER_IMAGE_NAME run_joern.sh
    # fi

    # # Run sonarqube
    # if [ -f "$OSS_FUZZ_OUT_DIR/sonarqube.sarif" ]; then
    #     echo "[+] Sonarqube results already exist for $PROJECT, skipping"
    # else
    #     echo "[+] Running sonarqube for $PROJECT"
    #     docker run -it $VOLUME_ARGS $DOCKER_IMAGE_NAME run_sonarqube.sh
    # fi

    # docker run -it $VOLUME_ARGS $DOCKER_IMAGE_NAME run_all.sh

    echo "[+] Docker image for $PROJECT finished"
done
