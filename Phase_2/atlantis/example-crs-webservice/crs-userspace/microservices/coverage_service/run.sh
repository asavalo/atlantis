#!/bin/bash

if command -v start-docker.sh 2>&1 >/dev/null
then
    echo "[Coverage Service] Ensuring DinD is running"
    start-docker.sh
else
    echo "[Coverage Service] start-docker.sh not found, skipping"
fi

$ATLANTIS_ARTIFACTS/./coverage_service 8 harness_builder_build_request coverage_service harness_builder_build_result coverage_service fuzzer_launch_announcement coverage_service fuzzer_seed_requests fuzzer_seed_updates coverage_service fuzzer_coverage_requests coverage_service fuzzer_coverage_responses "$(pwd)/runtime_cache"