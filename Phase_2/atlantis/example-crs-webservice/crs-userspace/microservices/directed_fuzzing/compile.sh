#!/bin/bash

set -e

# this must be unset to compile bullseye; otherwise CFLAGS might contain
# sanitizer flags which are incompatible for compiling llvm passes
unset CXXFLAGS
unset CFLAGS

pushd /directed_fuzzing/Bullseye/third_party/SVF-llvm-18
  export SVF_DIR=$PWD

  rm -rf Release-build/
  mkdir Release-build/
  pushd Release-build
    cmake -D CMAKE_BUILD_TYPE:STRING="Release" \
      -DCMAKE_CXX_FLAGS="-stdlib=libstdc++" \
      -DSVF_ENABLE_ASSERTIONS:BOOL=true  ../
    cmake --build . -j$(nproc)
  popd
popd

pushd /directed_fuzzing/Bullseye
  make clean
  make all -j$(nproc)

  # This is a separate pass to fix the ASAN issue when building
  # from a bitcode file: https://github.com/google/sanitizers/issues/1476
  $CC -fPIC -shared -o "AddSan.so" AddSan.cc `llvm-config-18 --cxxflags`
popd

pushd /directed_fuzzing/libfuzzer_utils
  make clean
  make
popd
