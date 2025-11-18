# use base image:
# - base-clang does not have llvm with share libs; and
#   it removes some needed binaries (checkout_build_install_llvm.sh:155)
FROM ghcr.io/aixcc-finals/base-image:v1.3.0

ARG arch=x86_64

ENV FUZZINTRO_OUTDIR=$SRC

RUN dpkg --add-architecture i386
RUN apt-get update && \
      apt-get install -y \
      software-properties-common \
      binutils-dev \
      build-essential \
      curl \
      wget \
      git \
      jq \
      patchelf \
      rsync \
      subversion \
      zip \
      libc6-dev-i386 \
      zlib1g-dev \
      libncurses5-dev \
      libgdbm-dev \
      libnss3-dev \
      libssl-dev \
      libsqlite3-dev \
      libreadline-dev \
      libffi-dev \
      libbz2-dev \
      liblzma-dev \
      llvm-18 \
      clang-18 \
      tini \
      libzstd-dev

# Install newer cmake.
# Many projects, as well as recent clang versions, need a newer cmake.
ENV CMAKE_VERSION 3.29.2
RUN wget -q https://github.com/Kitware/CMake/releases/download/v$CMAKE_VERSION/cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    chmod +x cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    ./cmake-$CMAKE_VERSION-Linux-$arch.sh --skip-license --prefix="/usr/local" && \
    rm cmake-$CMAKE_VERSION-Linux-$arch.sh && \
    rm -rf /usr/local/doc/cmake /usr/local/bin/cmake-gui

# Install Python 3.12
RUN apt-add-repository ppa:deadsnakes/ppa
RUN apt-get update && apt-get install -y \
    python3.12 python3.12-dev python3.12-venv
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12

# Install Protobuf compiler
RUN apt-get update && apt-get install -y wget unzip && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

# Create venv
RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Build libatlantis
RUN mkdir -p /libs
COPY ./libs/libCRS /libs/libCRS
COPY ./libs/libMSA /libs/libMSA
COPY ./libs/libatlantis /libs/libatlantis
RUN /venv/bin/pip3 install mypy-protobuf==3.6.0
RUN /libs/libatlantis/build.sh

# Copy and install necessary directories
RUN /venv/bin/pip3 install /libs/libCRS
RUN /venv/bin/pip3 install /libs/libMSA/python
RUN /venv/bin/pip3 install /libs/libatlantis

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# Copy package
COPY ./microservices/directed_fuzzing /directed_fuzzing

# Install the package
RUN /venv/bin/pip3 install zstandard==0.23.0
RUN /venv/bin/pip3 install --no-cache-dir /directed_fuzzing

WORKDIR /directed_fuzzing

# set compiler env
ENV CC=clang-18
ENV CXX=clang++-18
ENV CCC=clang++-18

# LLVM configuration
ENV LLVM_CONFIG=llvm-config-18

# AFL configuration
ENV AFL_CC=clang-18
ENV AFL_CXX=clang++-18
ENV AFL_NO_X86=1
ENV AFL_IGNORE_UNKNOWN_ENVS=1
ENV AFL_LLVM_INSTRUMENT="afl"

# Compile Bullseye
RUN /directed_fuzzing/compile.sh

# this has to be done after compiling SVF
# which uses gcc's stdlib
RUN apt-get install -y libc++-18-dev \
      libc++abi-18-dev

# set the CFLAGS just like in base-builder & base-clang
ENV CFLAGS -O1 \
  -fno-omit-frame-pointer \
  -gline-tables-only \
  -Wno-error=enum-constexpr-conversion \
  -Wno-error=incompatible-function-pointer-types \
  -Wno-error=int-conversion \
  -Wno-error=deprecated-declarations \
  -Wno-error=implicit-function-declaration \
  -Wno-error=implicit-int \
  -Wno-error=vla-cxx-extension \
  -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

ENV CXXFLAGS_EXTRA "-stdlib=libc++"
ENV CXXFLAGS "$CFLAGS $CXXFLAGS_EXTRA"

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/venv/bin/python3", "-m", "directed_fuzzing"]
