#!/bin/bash

set -ex

if [ $# -eq 0 ]
  then
    echo "[!] Provide the version of LLVM you wish compile for."
    echo "For example, to compile for llvm-11 use:"
    echo "\$ $0 11"
    exit -1
fi

# set up the llvm env
LLVM_VERSION=$1
if [ $LLVM_VERSION -ne 4 ]; then
  export LLVM_COMPILER=clang LLVM_CC_NAME="clang-$LLVM_VERSION" LLVM_CXX_NAME="clang++-$LLVM_VERSION" LLVM_AR_NAME="llvm-ar-$LLVM_VERSION" LLVM_LINK_NAME="llvm-link-$LLVM_VERSION" CC=wllvm CXX=wllvm++ LLVM_OPT="opt-$LLVM_VERSION"
else
  ROOT_DIR="$(git rev-parse --show-toplevel)"
  LLVM4_BIN_DIR="$ROOT_DIR/fuzzers/Beacon/Beacon/llvm4/bin"
  export LLVM_COMPILER=clang LLVM_CC_NAME="$LLVM4_BIN_DIR/clang" LLVM_CXX_NAME="$LLVM4_BIN_DIR/clang++" LLVM_AR_NAME="$LLVM4_BIN_DIR/llvm-ar" LLVM_LINK_NAME="$LLVM4_BIN_DIR/llvm-link" CC=wllvm CXX=wllvm++
fi

# read in config
SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
SRC_TAG="$(cat $SCRIPT_DIR/src-tag.txt)"
FUZZED_BIN="$(cat $SCRIPT_DIR/fuzz-bin.txt)"
BUILD_PATH="$SCRIPT_DIR/build-llvm-$1"

# cp the source to this target build
rm -rf "$BUILD_PATH"
cp -r "$SCRIPT_DIR/../$SRC_TAG/" "$BUILD_PATH"

# build
pushd $BUILD_PATH
  export CFLAGS="-fcommon -fPIE -g -fno-omit-frame-pointer -Wno-error"
  ./configure && make
popd

# extract the llvm bitcode
extract-bc $BUILD_PATH/$FUZZED_BIN

#export LLVM_COMPILER=clang
#export LLVM_CC_NAME=clang-11
#export LLVM_CXX_NAME=clang++-11
#export LLVM_LINK_NAME=llvm-link-11
