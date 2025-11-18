mkdir -p build
cd build
cmake .. \
	-DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
	-DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_CXX_COMPILER=clang++
make -j$(nproc)
