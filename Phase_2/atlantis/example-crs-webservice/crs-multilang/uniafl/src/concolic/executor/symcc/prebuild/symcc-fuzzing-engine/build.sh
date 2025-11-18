#!/bin/bash
set -e
cd $(dirname "$0")
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j $(nproc)
cd ..
cp build/libSymCCFuzzingEngine.a libSymCCFuzzingEngine.a
