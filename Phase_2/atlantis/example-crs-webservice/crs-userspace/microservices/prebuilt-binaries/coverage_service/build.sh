#!/bin/bash

set -e

cd `dirname $0`

if [ "$CARGO_BUILD_FLAGS" == "--release" ]; then
    export ARTIFACT_PATH=target/release/coverage_service
else
    export ARTIFACT_PATH=target/debug/coverage_service
fi

cargo build $CARGO_BUILD_FLAGS

cp $ARTIFACT_PATH coverage_service
