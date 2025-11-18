#!/bin/bash

SCRIPT_DIR=$(dirname "$0")

set -e -o pipefail
CRS_TARGET="aixcc/c/mock-c"
PROJECT_LANGUAGE="c"
CP_DIR="./cp_tarballs/mock-c-full"
PORT=8000
TASK_ID=$(uuidgen)
KEEP_DOCKER_CACHE=False
DETACH_MAIN_CONTAINER=False

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "    -h    Show this help message"
    echo "    -l    Project language (default: \"c\")"
    echo "    -o    Path to the challenge project tarballs directory (default: \"./cp_tarballs/mock-c-full\")"
    echo "    -r    CRS Target Project (default: \"${CRS_TARGET}\")"
    echo "    -a    Application name (optional)"
    echo "    -p    Port to run the main container on (default: 8000)"
    echo "    -k    Keep docker cache (default: false)"
    echo "    -d    Detach main container from the terminal (default: false)"
    echo "    -t    Task ID (default: random uuid)"
    echo "    -e    Additional environment variables (key=value)"
    exit 1
}

parse_args() {
    while getopts "ht:l:o:r:p:kde:" opt; do
        case $opt in
            h) usage ;;
            l) PROJECT_LANGUAGE=$OPTARG ;;
            o) CP_DIR=$OPTARG ;;
            r) CRS_TARGET=$OPTARG ;;
            p) PORT=$OPTARG ;;
            k) KEEP_DOCKER_CACHE=True ;;
            d) DETACH_MAIN_CONTAINER=True ;;
            t) TASK_ID=$OPTARG ;;
            e) ENVIRONMENTS+=("$OPTARG") ;;
            \?) echo "Invalid option: -$OPTARG"; usage ;;
            :) echo "Option -$OPTARG requires an argument"; usage ;;
        esac
    done
    if [ -z "$CP_DIR" ]; then
        echo "Ensure -o (CP_DIR) is set"
        usage
    fi
    
    CP_DIR=$(realpath "$CP_DIR")
}

get_env_vars() {
    if [ -f packages/crs_patch/.env ]; then
        source packages/crs_patch/.env
    fi

    for envvar in LITELLM_API_KEY LITELLM_API_BASE REGISTRY IMAGE_VERSION TARBALL_DIR VAPI_HOST ADAPTER_API_BASE; do
        if [ -z "${!envvar}" ]; then
            echo "Ensure $envvar variable is set"
            exit 2
        fi
    done
}

create_network() {
    if ! docker network ls | grep -q crs-network; then
        echo "Creating crs-network"
        docker network create crs-network
    fi
    GATEWAY_IP=$(docker network inspect crs-network -f '{{(index .IPAM.Config 0).Gateway}}')
}

run_main_container() {
    if [ "$KEEP_DOCKER_CACHE" = True ]; then
        DOCKER_DATA_VOLUME="-v $SCRIPT_DIR/.cache/crs-patch/docker-data-main:/var/lib/docker:delegated"
    else
        DOCKER_DATA_VOLUME=""
    fi
    ENVIRONMENTS_STRING=""
    for envvar in "${ENVIRONMENTS[@]}"; do
        ENVIRONMENTS_STRING+="-e $envvar "
    done
    docker run --name crs-patch-main-$TASK_ID \
        -p "$PORT:80" \
        -e CRS_TARGET="$CRS_TARGET" \
        -e TARBALL_DIR="$TARBALL_DIR" \
        -e VAPI_HOST="$VAPI_HOST" \
        -e AIXCC_OTLP_ENDPOINT="$AIXCC_OTLP_ENDPOINT" \
        -e TASK_ID="$TASK_ID" \
        $ENVIRONMENTS_STRING \
        -v "$CP_DIR:$TARBALL_DIR" \
        --add-host=host.docker.internal:"$GATEWAY_IP" \
        $DOCKER_DATA_VOLUME \
        --network "crs-network" \
        --privileged \
        -d crs-patch-main
}

run_sub_container() {
    ID=$1
    MODULE=$2
    SUB_PORT=$3
    if [ "$KEEP_DOCKER_CACHE" = True ]; then
        DOCKER_DATA_VOLUME="-v $SCRIPT_DIR/.cache/crs-patch/docker-data-$ID:/var/lib/docker:delegated"
    else
        DOCKER_DATA_VOLUME=""
    fi
    ENVIRONMENTS_STRING=""
    for envvar in "${ENVIRONMENTS[@]}"; do
        ENVIRONMENTS_STRING+="-e $envvar "
    done
    docker run --name "crs-patch-sub-$ID-$TASK_ID" \
        -p "$SUB_PORT:80" \
        -e CRS_TARGET="$CRS_TARGET" \
        -e LITELLM_API_KEY="$LITELLM_API_KEY" \
        -e LITELLM_API_BASE="$LITELLM_API_BASE" \
        -e APP_NAME="$ID" \
        -e APP_MODULE="$MODULE" \
        -e REGISTRY="$REGISTRY" \
        -e IMAGE_VERSION="$IMAGE_VERSION" \
        -e PROJECT_LANGUAGE="$PROJECT_LANGUAGE" \
        -e TARBALL_DIR="$TARBALL_DIR" \
        -e AIXCC_OTLP_ENDPOINT="$AIXCC_OTLP_ENDPOINT" \
        -e TASK_ID="$TASK_ID" \
        -e ADAPTER_API_BASE="$ADAPTER_API_BASE" \
        $ENVIRONMENTS_STRING \
        -v "$CP_DIR:$TARBALL_DIR" \
        -v ~/.docker/config.json:/root/.docker/config.json \
        $DOCKER_DATA_VOLUME \
        --network "crs-network" \
        --privileged \
        -d crs-patch-sub
}


main() {
    parse_args "$@"
    get_env_vars
    
    create_network

    mkdir -p "$SCRIPT_DIR/.cache/crs-patch/"

    echo "Running sub containers"
    i=1
    cat packages/crs_patch/configs.json | jq -r '.[] | "\(.id) \(.module)"' | while read -r ID MODULE; do
        run_sub_container "$ID" "$MODULE" "$((PORT + i))"
        ((i++))
    done
    sleep 5

    echo "Running main container"
    run_main_container

    if [ "$DETACH_MAIN_CONTAINER" = False ]; then
        docker attach crs-patch-main-$TASK_ID

        docker stop crs-patch-main-$TASK_ID
        cat packages/crs_patch/configs.json | jq -r '.[] | "\(.id)"' | while read -r ID; do
            docker stop "crs-patch-sub-$ID-$TASK_ID"
        done
    fi
}

main "$@"
