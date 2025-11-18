FROM ghcr.io/aixcc-finals/base-builder:v1.3.0
# ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq
RUN apt-get install -y build-essential make cmake ninja-build git python3 python3-dev python3-pip autoconf libtool libzstd-dev texinfo bison flex pkg-config wget gawk gnupg lsb-release
#libc++-18-dev libc++abi-18-dev


WORKDIR $SRC

# Build llvm-project as same as oss-fuzz's clang version

RUN git clone https://github.com/llvm/llvm-project.git

RUN cd llvm-project && \
    git checkout c13b7485b87909fcf739f62cfa382b55407433c0 && \
    mkdir build && cd build && \
    cmake -G Ninja ../llvm \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/lib/llvm-18 \
    -DLLVM_ENABLE_ASSERTIONS=OFF \
    -DLLVM_ENABLE_ABI_BREAKING_CHECKS=OFF \
    -DLLVM_INCLUDE_RT_INCLUDE_TESTS=off \
    -DCMAKE_CXX_FLAGS="-stdlib=libstdc++" \
    -DCMAKE_EXE_LINKER_FLAGS="-stdlib=libstdc++" \
    -DCMAKE_SHARED_LINKER_FLAGS="-stdlib=libstdc++" \
    -DLLVM_BUILD_LLVM_DYLIB=ON \
    -DLLVM_LINK_LLVM_DYLIB=ON \
    -DLLVM_ENABLE_RTTI=ON \
    -DLLVM_ENABLE_FFI=ON \
    -DLLVM_APPEND_VC_REV=OFF \
    -DLLVM_TARGETS_TO_BUILD="X86" && \
    ninja -j$(nproc) && ninja install


# Adjust PATH for prevent confusing llvm library
# ENV PATH="/usr/lib/llvm-18/lib:/usr/lib/llvm-18/bin:$PATH"

ENV SVF=/src/SVF

# Upgrade binutils
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.42.tar.gz && \
    tar xvf binutils-2.42.tar.gz && \
    cd binutils-2.42 && \
    mkdir build && \
    cd build && \
    ../configure --prefix=/usr/local && \
    make -j$(nproc) && \
    make install

ENV LLVM_DIR=/usr/lib/llvm-18/lib/cmake
ENV LLVM_COMPILER=clang
ENV LLVM_CC_NAME=clang
ENV LLVM_CXX_NAME=clang++
ENV LLVM_LINK_NAME=/usr/lib/llvm-18/bin/llvm-link
ENV CC=clang
ENV CXX=clang++

# Build SVF
COPY SVF-llvm-18 $SVF
RUN cd $SVF && bash ./build.sh

