#!/bin/bash

DOCKER_CRS_SARIF_TRACER_C=sarif-tracer-c
DOCKER_CRS_SARIF_TRACER_JAVA=sarif-tracer-java


if [ $# -ne 4 ]; then
    echo "Usage: $0 [c|jvm] tracer_output_dir corpus_dir harness_dir"
    exit 1
fi

if [ $1 == "c" ]; then
    DOCKER_TRACER=$DOCKER_CRS_SARIF_TRACER_C
elif [ $1 == "jvm" ]; then
    DOCKER_TRACER=$DOCKER_CRS_SARIF_TRACER_JAVA
else
    echo "Invalid tracer type: $1"
    exit 1
fi

tracer_inner_output_dir="/${2//\//_}"
tracer_inner_corpus_dir="/${3//\//_}"

docker run -v $2:$tracer_inner_output_dir \
    -v $3:$tracer_inner_corpus_dir \
    -v $4:/out \
    -it \
    -e CRS_SARIF_TRACER_TRACE_OUTPUTDIR=$tracer_inner_output_dir \
    -e CRS_SARIF_TRACER_CORPUS_DIRECTORY=$tracer_inner_corpus_dir \
    $DOCKER_TRACER

