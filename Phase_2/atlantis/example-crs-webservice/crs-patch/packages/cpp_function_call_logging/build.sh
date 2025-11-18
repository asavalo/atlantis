#!/bin/sh

set -e
rm -rf build
mkdir -p build
cd build
cmake .. -DCMAKE_CXX_FLAGS="-w" -DLOG_FILE_PATH=$LOG_FILE_PATH
make -j$(nproc)

# only remain the executable file
rm -rf CMakeFiles
rm -f CMakeCache.txt
rm -f cmake_install.cmake
rm -f Makefile
