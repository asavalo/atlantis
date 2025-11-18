#!/bin/bash
# Run server

if [ $# -eq 0 ]; then
    echo "Usage: ./run.sh ./scripts/benchmark/full/custom-c-mock-c-cpv-0-*.toml"
    exit 1
fi

export DETECTIONS=$(echo "$@" | tr ' ' ',')
uv run uvicorn scripts.crs_test.server:app --host 0.0.0.0 --port 8088