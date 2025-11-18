#!/bin/bash

set -e

cd $(dirname $0)
pushd prebuild
pushd z3
if [ ! -f "build/libz3.a" ]; then
    ./build.sh
fi
popd

pushd concolic_executor
if [ ! -f "libsymcc-rt.so" ]; then
    ./build.sh
fi
popd

pushd atlantis_cc
if [ ! -f "cc_wrapper" ]; then
    ./build.sh
fi
popd

pushd symcc-pass
if [ ! -f "build/libsymcc.so" ]; then
    ./build.sh
fi	
popd

pushd symqemu-multilang
if [ ! -f "build/qemu-x86_64" ]; then
    ./build.sh
fi

pushd multilang_test
./patch-qemu.sh
popd

popd

popd

pushd test-harness
./build.sh
popd

cp test-harness/test-harness* symcc_binaries 
cp prebuild/concolic_executor/libsymcc-rt.so symcc_binaries
cp prebuild/symqemu-multilang/build/qemu-x86_64 symcc_binaries
cp -r prebuild/symqemu-multilang/scripts symcc_binaries
prebuild/patchelf --set-rpath $(realpath symcc_binaries) symcc_binaries/test-harness
