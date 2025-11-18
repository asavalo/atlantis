FROM cruizba/ubuntu-dind@sha256:9cf8e63414de9e1536570ae6907560d4c84a682225755bc20978d949ec7e020e

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    wget curl \
    lsb-release \
    software-properties-common \
    cmake \
    git \
    make \
    zlib1g-dev \
    bsdmainutils \
    netcat \
    rsync

# Install yq
ARG YQ_VERSION=4.43.1
ARG YQ_BINARY=yq_linux_amd64
RUN wget -q https://github.com/mikefarah/yq/releases/download/v${YQ_VERSION}/${YQ_BINARY} -O /usr/bin/yq && \
    chmod +x /usr/bin/yq

RUN apt-add-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y \
    wget unzip python3.12 python3.12-dev python3.12-venv && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12 && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

ENV PATH="/venv/bin:$PATH"

COPY ./libs /libs
COPY ./microservices/harness_builder /harness_builder

RUN python3.12 -m venv /venv && \
    /venv/bin/pip3 install mypy-protobuf==3.6.0 && \
    /libs/libatlantis/build.sh && \
    /venv/bin/pip3 install /libs/libCRS && \
    /venv/bin/pip3 install /libs/libMSA/python && \
    /venv/bin/pip3 install hatch && \
    /venv/bin/pip3 install /libs/libatlantis && \
    /venv/bin/pip3 install /harness_builder

WORKDIR /harness_builder

ENV PYTHONUNBUFFERED=1
CMD ["./run.sh"]