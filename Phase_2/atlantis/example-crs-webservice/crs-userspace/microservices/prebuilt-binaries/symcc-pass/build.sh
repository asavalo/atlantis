#!/bin/sh

set -e
cd `dirname $0`

mkdir -p build
cd build
cmake .. -DCMAKE_CXX_FLAGS="-w" -DNDEBUG=1
make -j$(nproc)

if [ -d "/out" ]; then
    cp ./libsymcc.so /work/
fi
