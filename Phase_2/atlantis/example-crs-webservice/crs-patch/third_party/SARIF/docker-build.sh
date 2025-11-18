#! /bin/bash
set -e

IMG_NAME="crs-sarif"

# Build "crs-sarif" image
docker build \
  --file "Dockerfile" \
  --tag "crs-sarif" \
  .

# Build "sarif-builder-jvm" image
docker build \
  --file "Dockerfile.jvm_builder" \
  --tag "sarif-builder-jvm" \
  .

# Build "sarif-builder" image
docker build \
  --file "Dockerfile.c_builder" \
  --tag "sarif-builder" \
  .

# Build "tracer-c" image
cd ./tracer/tracer-c
docker build \
  --file "Dockerfile" \
  --tag "sarif-tracer-c" \
  .
cd ../../

# Build "tracer-java" image
cd ./tracer/tracer-java
docker build \
  --file "Dockerfile" \
  --tag "sarif-tracer-java" \
  .
cd ../../
