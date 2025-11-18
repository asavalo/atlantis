#!/bin/sh

set -e
cd `dirname $0`

# if DEBUG is not set,
if [ -z "${DEBUG}" ]; then
    echo "[*] DEBUG is not set. Building in release mode."
    DEBUGFLAGS="-DNDEBUG=1"
else
    echo "[*] DEBUG is set. Building with debug mode."
fi

mkdir -p build
cd build
cmake .. -DCMAKE_CXX_FLAGS="-w $DEBUGFLAGS" -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
make -j$(nproc)

if [ -d "/work" ]; then
    cp ./libsymcc.so /work/
fi
