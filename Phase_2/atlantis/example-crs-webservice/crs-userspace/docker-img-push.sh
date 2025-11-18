#!/bin/bash

REGISTRY=$1
VERSION=$2

CRS_BUILD_CP_IMAGE=0 python3 docker-run.py push --registry $REGISTRY/crs-userspace --tag $VERSION