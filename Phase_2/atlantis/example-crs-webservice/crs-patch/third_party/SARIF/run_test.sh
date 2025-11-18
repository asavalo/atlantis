#!/bin/sh
poetry run python crs_test.py \
    --project-name mock-java \
    --project-language jvm \
    --original-oss-fuzz-dir /home/user/work/oss-fuzz \
    --working-oss-fuzz-dir /home/user/work/oss-fuzz-sarif \
    --crs-test-dir /home/user/work/crs-test \
    --tarball-dir /home/user/work/SARIF/cp_tarballs \
    --run-sarif-build 
    # --run-docker-build \
    # --run-sarif-build \
    # --run-crs
