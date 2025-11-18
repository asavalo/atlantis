#!/bin/bash

# Start docker, check if dind is running
start-docker.sh

source /venv/bin/activate
export PYTHONUNBUFFERED=1
custom_fuzzer &
wait
