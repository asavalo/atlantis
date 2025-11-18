#!/bin/bash -eux

DIR=$(dirname $0)

#docker build -t ghcr.io/aixcc-finals/base-runner "$@" $DIR/base-runner
#docker build -t ghcr.io/aixcc-finals/base-image "$@" $DIR/base-image
cp $DIR/../../../../uniafl/src/msa/manager/manager.c $DIR/multilang-clang/manager.cpp
cp $DIR/../../../../uniafl/src/msa/manager/manager.h $DIR/multilang-clang/manager.h
rsync -av --delete \
	$DIR/../../../../uniafl/src/concolic/executor/symcc/prebuild/ \
	--exclude='concolic_executor/target/' \
	--exclude='concolic_executor/libsymcc-rt.so' \
	--exclude='concolic_executor/symcc-venv/' \
	--exclude='cpython-3.14/build' \
	--exclude='LibAFL/target/' \
	--exclude='z3/build' \
	--exclude='symcc-pass/build/' \
	--exclude='atlantis_cc/target/' \
	--exclude='atlantis_cc/*_wrapper' \
	--exclude='symqemu-multilang/build/' \
	--exclude='symqemu-multilang/symqemu-venv/' \
	--exclude='symqemu-multilang/**/.cache/' \
	--exclude='glib-2.66/_build/' \
	--exclude='glib-2.66/meson-venv/' \
	--exclude='symcc-fuzzing-engine/build/' \
	$DIR/base-builder/symcc-binaries/ 2>&1 > /dev/null
pushd $DIR/base-builder/symcc-binaries && ./clean.sh && popd
docker build -t multilang-clang "$@" $DIR/multilang-clang || exit -1
docker build -t multilang-builder "$@" -f $DIR/base-builder/Dockerfile.multilang $DIR/base-builder || exit -1
docker build -t multilang-builder-jvm "$@" -f $DIR/base-builder-jvm/Dockerfile.multilang $DIR/base-builder-jvm || exit -1
#docker build -t multilang-builder-rust "$@" -f $DIR/base-builder-rust/Dockerfile.multilang $DIR/base-builder-rust
#docker build -t multilang-builder-go "$@" -f $DIR/base-builder-go/Dockerfile.multilang $DIR/base-builder-go
#docker build -t multilang-builder-python "$@" -f $DIR/base-builder-python/Dockerfile.multilang $DIR/base-builder-python
#TODO
#docker build -t gcr.io/oss-fuzz-base/base-builder-jvm "$@" infra/base-images/base-builder-jvm
#docker build -t gcr.io/oss-fuzz-base/base-builder-python "$@" infra/base-images/base-builder-python
#docker build -t gcr.io/oss-fuzz-base/base-builder-rust "$@" infra/base-images/base-builder-rust
#docker build -t gcr.io/oss-fuzz-base/base-builder-ruby "$@" infra/base-images/base-builder-ruby
#docker build -t gcr.io/oss-fuzz-base/base-builder-swift "$@" infra/base-images/base-builder-swift
#docker build -t gcr.io/oss-fuzz-base/base-runner "$@" infra/base-images/base-runner
#docker build -t gcr.io/oss-fuzz-base/base-runner-debug "$@" infra/base-images/base-runner-debug
