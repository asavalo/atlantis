#!/bin/bash
set -e

HOST_SOURCE_DIR="/workspace/cp-manager_dir/src/${REPO_NAME}"
CONTAINER_WORKDIR="/src/${CRS_TARGET}"

mkdir -p ${HOST_SOURCE_DIR}
cp -r ${HOST_SOURCE_DIR}/* ${CONTAINER_WORKDIR}/

echo "[*] COPY from $HOST_SOURCE_DIR* to $CONTAINER_WORKDIR"
