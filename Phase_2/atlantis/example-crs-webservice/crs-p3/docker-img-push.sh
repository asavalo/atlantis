#!/bin/bash
set -e

REGISTRY=$1
IMAGE_VERSION=$2

docker tag crs-p3 $REGISTRY/crs-p3:$IMAGE_VERSION
docker push $REGISTRY/crs-p3:$IMAGE_VERSION
