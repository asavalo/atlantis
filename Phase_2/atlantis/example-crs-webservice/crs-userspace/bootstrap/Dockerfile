# libc-2.31 / Don't change this. Using old ubuntu/libc is for compatibility with subsequent libc versions
FROM ubuntu:20.04@sha256:fa17826afb526a9fc7250e0fbcbfd18d03fe7a54849472f86879d8bf562c629e AS base

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

ARG PREBUILT_BINARIES=./microservices/prebuilt-binaries

RUN apt-get update -y && apt-get install -y \
    build-essential \
    wget \
    curl \
    lsb-release \
    software-properties-common \
    cmake \
    protobuf-compiler \
    git \
    make \
    bsdmainutils \
    netcat \
    ninja-build \
    gnupg \
    libzstd-dev \
    colordiff \
    xxd \
    wdiff \
    zlib1g-dev \
    pkg-config

# Install python3.12
RUN apt-add-repository ppa:deadsnakes/ppa && \
    apt-get update -y && \ 
    apt-get install -y python3.12 python3.12-dev python3.12-venv
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12

# Install glib from source
WORKDIR /root
COPY $PREBUILT_BINARIES/glib-2.66 /root/glib-2.66
COPY $PREBUILT_BINARIES/install-glib.sh /root/install-glib.sh
RUN ./install-glib.sh

# Install zlib from source
COPY $PREBUILT_BINARIES/zlib-1.2.13 /root/zlib-1.2.13
COPY $PREBUILT_BINARIES/install-zlib.sh /root/install-zlib.sh
RUN ./install-zlib.sh

# Install yq
ARG YQ_VERSION=4.43.1
ARG YQ_BINARY=yq_linux_amd64
RUN wget -q https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/${YQ_BINARY} -O /usr/bin/yq && \
    chmod +x /usr/bin/yq

# Install LLVM: for now, let's improvise to 18
ENV LLVM_VERSION=18
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh ${LLVM_VERSION} all && \
    ln -s /usr/bin/clang-${LLVM_VERSION} /usr/bin/clang && \
    ln -s /usr/bin/clang++-${LLVM_VERSION} /usr/bin/clang++ && \
    ln -s /usr/lib/llvm-${LLVM_VERSION}/lib/libc++.a /usr/lib/libc++.a

# Install llvm-15 for symqemu
ARG SYMQEMU_LLVM_VERSION=15
RUN ./llvm.sh ${SYMQEMU_LLVM_VERSION}

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain 1.87
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Docker 
RUN set -eux; \
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc; \
    chmod a+r /etc/apt/keyrings/docker.asc; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
        $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null; \
    DEBIAN_FRONTEND=noninteractive apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        containerd.io \
        docker-ce \
        docker-ce-cli \
        docker-buildx-plugin; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*


COPY $PREBUILT_BINARIES/z3 /root/z3
WORKDIR /root/z3
RUN ./build.sh

COPY $PREBUILT_BINARIES/LibAFL /root/LibAFL
COPY ./libs/libMSA/rust/libmsa /libs/libMSA/rust/libmsa
COPY ./libs/libatlantis/proto /libs/libatlantis/proto
ENV PROTO_DIR=/libs/libatlantis/proto

# Build concolic_executor and fuzzer libraries
COPY $PREBUILT_BINARIES/pseudofuzzer /root/pseudofuzzer
WORKDIR /root/pseudofuzzer
RUN ./build.sh

COPY $PREBUILT_BINARIES/fuzzer /root/fuzzer
WORKDIR /root/fuzzer
RUN ./build.sh

##COPY $PREBUILT_BINARIES/concolic_executor /root/concolic_executor
#WORKDIR /root/concolic_executor
#RUN ./build.sh
#
##COPY $PREBUILT_BINARIES/concolic_executor_symqemu /root/concolic_executor_symqemu
#WORKDIR /root/concolic_executor_symqemu
#RUN ./build.sh

COPY $PREBUILT_BINARIES/atlantis_cc /root/atlantis_cc
WORKDIR /root/atlantis_cc
RUN ./build.sh

COPY $PREBUILT_BINARIES/coverage_service /root/coverage_service
WORKDIR /root/coverage_service
RUN ./build.sh

##COPY $PREBUILT_BINARIES/concolic_mutation_service /root/concolic_mutation_service
#WORKDIR /root/concolic_mutation_service
#RUN ./build.sh
#
##RUN python3.12 -m venv /symqemu-venv
#RUN /symqemu-venv/bin/pip3 install meson tomli
#RUN <<EOF cat > /configure_symqemu.sh
#../configure                                                    \
#      --audio-drv-list=                                         \
#      --disable-sdl                                             \
#      --disable-gtk                                             \
#      --disable-vte                                             \
#      --disable-opengl                                          \
#      --disable-virglrenderer                                   \
#      --target-list=x86_64-linux-user                           \
#      --symcc-rt-llvm-version="$SYMQEMU_LLVM_VERSION"                   \
#      --disable-werror					        \
#      --python=/symqemu-venv/bin/python3
#EOF
#
##RUN chmod u+x /configure_symqemu.sh
#COPY $PREBUILT_BINARIES/symqemu /root/symqemu
#WORKDIR /root/symqemu
#RUN mkdir build && cd build && /configure_symqemu.sh
#RUN cd build && ninja 
#
##COPY $PREBUILT_BINARIES/symcc-pass /root/symcc-pass
#
## Patchelf symqemu
##COPY $PREBUILT_BINARIES/patchelf/patchelf /patchelf
#RUN /patchelf --replace-needed libSymCCRtShared.so libsymcc-rt-symqemu.so /root/symqemu/build/qemu-x86_64

# RUN mkdir -p /artifacts
# RUN cp /root/pseudofuzzer/libfuzzer.so /artifacts/libpseudofuzzer.so
# RUN cp /root/fuzzer/libfuzzer.so /artifacts/libfuzzer.so
# RUN cp /root/coverage_service/coverage_service /artifacts/coverage_service
# #RUN cp /root/concolic_executor/libsymcc-rt.so /artifacts/libsymcc-rt.so
# #RUN cp /root/concolic_executor_symqemu/libsymcc-rt.so /artifacts/libsymcc-rt-symqemu.so
# #RUN cp /root/concolic_executor_symqemu/libfuzzer-symqemu.so /artifacts/libfuzzer-symqemu.so
# RUN cp /root/atlantis_cc/cc_wrapper /artifacts/cc_wrapper
# RUN cp /root/atlantis_cc/cxx_wrapper /artifacts/cxx_wrapper
# #RUN cp /root/concolic_mutation_service/concolicd /artifacts/concolicd
# #RUN cp /root/symqemu/build/qemu-x86_64 /artifacts/qemu-x86_64
# #RUN cp -r /root/symcc-pass/ /artifacts/symcc-pass
# RUN cp /usr/lib/libc++.a /artifacts/libc++.a
# RUN cp /root/z3/build/libz3.a /artifacts/libz3.a

RUN mkdir -p /artifacts && \
    cp /root/pseudofuzzer/libfuzzer.so /artifacts/libpseudofuzzer.so && \
    cp /root/fuzzer/libfuzzer.so /artifacts/libfuzzer.so && \
    cp /root/coverage_service/coverage_service /artifacts/coverage_service && \
    cp /root/atlantis_cc/cc_wrapper /artifacts/cc_wrapper && \
    cp /root/atlantis_cc/cxx_wrapper /artifacts/cxx_wrapper && \
    cp /usr/lib/libc++.a /artifacts/libc++.a && \
    cp /root/z3/build/libz3.a /artifacts/libz3.a

# NOTE previously v1.1.0
FROM ghcr.io/aixcc-finals/base-builder:v1.3.0 AS archive-llvm

RUN mkdir -p /directed_build_deps /tmp
RUN python3 -m venv /directed_build_deps/venv
RUN /directed_build_deps/venv/bin/pip3 install wllvm

RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y \
    llvm-18 \
    clang-18 \
    libzmq3-dev

COPY ./microservices/directed_fuzzing/archive_llvm.py /tmp/archive_llvm.py
COPY ./microservices/directed_fuzzing/custom_compile.sh /directed_build_deps/custom_compile.sh
COPY ./microservices/directed_fuzzing/directed-fuzzer-c-compiler.py /directed_build_deps/directed-fuzzer-c-compiler.py
COPY ./microservices/directed_fuzzing/directed-fuzzer-c++-compiler.py /directed_build_deps/directed-fuzzer-c++-compiler.py
# tars depedencies into /directed_build_deps/packages.tar.gz
RUN python3 /tmp/archive_llvm.py /directed_build_deps \
    binfmt-support clang-18 file icu-devtools libasan6 libclang-common-18-dev \
    libclang-cpp18 libclang-rt-18-dev libclang1-18 libffi-dev libgc1c2 \
    libgcc-10-dev libicu-dev libicu66 libllvm18 libmagic-mgc libmagic1 libmpdec2 \
    libncurses-dev libobjc-10-dev libobjc4 libpfm4 libpipeline1 libpython3-stdlib \
    libpython3.8-minimal libpython3.8-stdlib libstdc++-10-dev libxml2 libxml2-dev \
    libyaml-0-2 libz3-4 libz3-dev llvm-18 llvm-18-dev llvm-18-linker-tools \
    llvm-18-runtime llvm-18-tools mime-support

RUN tar cf /directed_build_deps.tar.gz /directed_build_deps

# Install custom AFL

RUN rm -rf /aflplusplus
RUN mkdir -p /aflplusplus
WORKDIR $SRC
RUN rm -rf aflpluplus
COPY ./microservices/prebuilt-binaries/AFLplusplus $SRC/aflplusplus
RUN precompile_afl

WORKDIR $SRC/aflplusplus/custom_mutators/zmq
RUN make

# inspired by compile_afl, only copy relevant artifacts
WORKDIR $SRC/aflplusplus
RUN cp libAFLDriver.a custom_compile.sh ./custom_mutators/zmq/libzmqmutator.so /aflplusplus
RUN ls afl-* *.txt *.a *.o *.so | sort -u | xargs cp -t /aflplusplus

RUN tar cf /aflplusplus.tar.gz /aflplusplus

FROM python:3.10-slim

RUN apt-get update && apt-get install -y git wget unzip rsync tar pigz && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

# Copy artifacts
RUN mkdir -p /data
COPY --from=base /artifacts /data/artifacts
COPY --from=archive-llvm /directed_build_deps.tar.gz /data/artifacts/directed_build_deps.tar.gz
COPY --from=archive-llvm /aflplusplus.tar.gz /data/artifacts/aflplusplus.tar.gz

# Copy necessary directories
RUN mkdir -p /libs
COPY ./libs/libCRS /libs/libCRS
COPY ./libs/libMSA /libs/libMSA
COPY ./libs/libatlantis /libs/libatlantis
COPY ./bootstrap /bootstrap

# Create venv
ENV PATH="/venv/bin:$PATH"
RUN python3 -m venv /venv && \
    /venv/bin/pip3 install mypy-protobuf==3.6.0 && \
    /libs/libatlantis/build.sh && \
    /venv/bin/pip3 install /libs/libCRS && \
    /venv/bin/pip3 install /libs/libMSA/python && \
    /venv/bin/pip3 install hatch && \
    /venv/bin/pip3 install /libs/libatlantis

# Workdir
WORKDIR /bootstrap

CMD ["./run.sh"]
