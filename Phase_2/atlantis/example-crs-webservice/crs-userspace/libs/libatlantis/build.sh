#!/bin/sh
cd "$(dirname "$0")"
protoc --python_out=./libatlantis --mypy_out=./libatlantis --proto_path ./proto ./proto/*.proto
