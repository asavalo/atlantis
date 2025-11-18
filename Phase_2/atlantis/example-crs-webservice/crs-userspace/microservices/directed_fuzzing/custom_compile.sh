#!/usr/bin/env bash

set -eu

# use same path
mkdir -p /directed_build_deps
cp -r /work/directed_build_deps/venv /directed_build_deps/venv

source /directed_build_deps/venv/bin/activate

# extract llvm-18
pushd /
tar xzf /work/directed_build_deps/packages.tar.gz
popd

# set up env vars
LLVM_VERSION=18
# FIXME try using a modified checkout_build_install_llvm.sh from oss-fuzz base-clang and keep the binaries
# - using LLVM_CC_NAME=clang-18 doesn't work due to missing -lc++ somehow
# - using LLVM_CC_NAME=clang    doesn't work at the extract-bc stage, cannot find .llvm_bc section. Maybe because mixing tools (clang vs. llvm-link-18)
export LLVM_COMPILER=clang \
  LLVM_CC_NAME="clang" \
  LLVM_CXX_NAME="clang++" \
  LLVM_AR_NAME="llvm-ar" \
  LLVM_LINK_NAME="llvm-link-$LLVM_VERSION" \
  LLVM_OPT="opt-$LLVM_VERSION"

export HARNESS_BINARIES="$@"

mkdir -p /out/directed-fuzzing

# dont compile with sanitizers.
# Instead, save them and add them after the directed fuzzer analysis.
if [[ -n "$SANITIZER" ]]; then
    export DF_HARNESS_SAN="$SANITIZER"
    export SANITIZER=""
fi

# we need a dummy main to make the linking work
clang++ -x c++ -c -o /out/directed-fuzzing/dummy-main.o - <<<'#include <stddef.h>
#include <stdint.h>
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) { return 0; }
extern "C" int main() { return 0; }'

# some projects do not respect the LIB_FUZZING_ENGINE env
cp /out/directed-fuzzing/dummy-main.o /usr/lib/libFuzzingEngine.a

# remove any coverage instrumentation
# those libs (ldl, pthread, etc) are implicitly
# linked when building with asan & fuzzer
# since we are clearing those options, we must add them manually
# so that programs that actually use them but dont
# explicitly set them compile ok (i.e. sqllite3)
export LIB_FUZZING_ENGINE="-lpthread -lrt -lm -ldl -lresolv /out/directed-fuzzing/dummy-main.o"
export FUZZING_ENGINE="none"
export CFLAGS="$CFLAGS -g"
export CXXFLAGS="$CXXFLAGS -g"

export CC=/work/directed_build_deps/directed-fuzzer-c-compiler.py \
  CXX=/work/directed_build_deps/directed-fuzzer-c++-compiler.py
compile

# extract bitcode for all args, MUST BE ABSOLUTE DIR
for arg in $@; do
    # extract-bc $arg || echo "extract-bc failed!!"
    extract-bc $arg
done
