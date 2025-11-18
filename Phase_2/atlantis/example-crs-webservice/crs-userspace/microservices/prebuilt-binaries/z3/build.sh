#!/bin/sh
mkdir build && \
cd build && \
cmake -G "Unix Makefiles" \
-DCMAKE_BUILD_TYPE=Release \
-DCMAKE_CXX_COMPILER=clang++ \
-DCMAKE_C_COMPILER=clang \
-DCMAKE_INSTALL_PREFIX=$out \
-DCMAKE_CXX_FLAGS="-stdlib=libc++" \
-DZ3_BUILD_LIBZ3_SHARED=OFF .. && \
make -j$(nproc) && \
make install