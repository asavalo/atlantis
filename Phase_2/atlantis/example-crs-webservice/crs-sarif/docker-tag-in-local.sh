# !/bin/bash

set -x

docker tag crs-sarif ghcr.io/team-atlanta/crs-sarif/crs-sarif
docker tag sarif-builder ghcr.io/team-atlanta/crs-sarif/sarif-builder
docker tag sarif-builder-codeql ghcr.io/team-atlanta/crs-sarif/sarif-builder-codeql
docker tag sarif-builder-jvm ghcr.io/team-atlanta/crs-sarif/sarif-builder-jvm
docker tag sarif-builder-codeql-jvm ghcr.io/team-atlanta/crs-sarif/sarif-builder-codeql-jvm
docker tag sarif-tracer-c ghcr.io/team-atlanta/crs-sarif/sarif-tracer-c
docker tag sarif-tracer-java ghcr.io/team-atlanta/crs-sarif/sarif-tracer-java
docker tag sarif-build-runner ghcr.io/team-atlanta/crs-sarif/sarif-build-runner