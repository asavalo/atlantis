#!/bin/bash
set -e

REGISTRY=$1
VERSION=$2

push() {
    docker image tag $1 $REGISTRY/crs-sarif/$1:$VERSION
    docker image push $REGISTRY/crs-sarif/$1:$VERSION
}


push "crs-sarif"
push "sarif-builder"
push "sarif-builder-codeql"
push "sarif-builder-jvm"
push "sarif-builder-codeql-jvm"
push "sarif-tracer-c"
push "sarif-tracer-java"
push "sarif-build-runner"