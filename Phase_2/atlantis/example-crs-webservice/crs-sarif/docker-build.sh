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

# Build "sarif-builder-codeql-jvm" image
docker build \
  --file "Dockerfile.jvm_codeql" \
  --tag "sarif-builder-codeql-jvm" \
  .

# Build "sarif-builder" image
docker build \
  --file "Dockerfile.c_builder" \
  --tag "sarif-builder" \
  .

# Build "sarif-builder-codeql" image
docker build \
  --file "Dockerfile.c_codeql" \
  --tag "sarif-builder-codeql" \
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

# Build "sarif-build-runner" image
docker build \
  --file "Dockerfile.sarif_build_runner" \
  --tag "sarif-build-runner" \
  .
