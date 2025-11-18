#!/bin/bash

# Store the current directory
ORIGINAL_DIR=$(pwd)

# Check if required arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <oss-fuzz-dir> <src-dir> <language>"
    echo "language should be either 'c' or 'java' or 'cpp'"
    exit 1
fi

OSS_FUZZ_DIR=$1
SRC_DIR=$2
LANGUAGE=$3

# Validate language parameter
if [ "$LANGUAGE" != "c" ] && [ "$LANGUAGE" != "java" ] && [ "$LANGUAGE" != "cpp" ]; then
    echo "Error: Language must be either 'c' or 'java' or 'cpp'"
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p "$SRC_DIR"

if [ "$LANGUAGE" == "java" ]; then
    LANGUAGE="jvm"
fi

# Set the project directory based on language
PROJECTS_DIR="$OSS_FUZZ_DIR/projects/aixcc/$LANGUAGE"

# List all projects in the directory
PROJECTS=$(ls $PROJECTS_DIR)

for PROJECT in $PROJECTS; do
    # Run CodeQL analysis
    echo "[+] Copying source code for $PROJECT"

    PROJECT_SRC_DIR="$SRC_DIR/$PROJECT/src"

    mkdir -p $SRC_DIR/$PROJECT

    if [ -d "$PROJECT_SRC_DIR" ]; then
        echo "[-] $PROJECT_SRC_DIR already exists"
        continue
    fi

    # Construct Docker image name
    DOCKER_IMAGE="gcr.io/oss-fuzz/aixcc/$LANGUAGE/$PROJECT"
    
    # Copy files from docker container to local directory
    echo "Copying files from $DOCKER_IMAGE:/src to $PROJECT_SRC_DIR"
    # Run the container first to get the container ID
    CONTAINER_ID=$(docker run -d --rm $DOCKER_IMAGE /bin/bash -c "sleep 10")
    
    # Copy files from the running container
    docker cp "$CONTAINER_ID:/src/." "$PROJECT_SRC_DIR"
    
    # Wait for the container to exit
    docker wait $CONTAINER_ID

    echo "----------------------------------------"
done

# chmod -R 755 $SRC_DIR