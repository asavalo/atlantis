FROM cruizba/ubuntu-dind@sha256:9cf8e63414de9e1536570ae6907560d4c84a682225755bc20978d949ec7e020e
LABEL name="custom_fuzzer"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    wget curl \
    software-properties-common \
    rsync zstd \
    tini \
    && apt-add-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y \
    python3.12 python3.12-dev python3.12-venv && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12 && \
    apt-get update && apt-get install -y wget unzip && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

ENV PATH="/venv/bin:$PATH"

# userspace-custom-fuzzers/build.py has to run before this

# Copy and install libs
COPY ./libs /libs
RUN python3.12 -m venv /venv && \
    /venv/bin/pip3 install --no-cache-dir mypy-protobuf==3.6.0 && \
    /libs/libatlantis/build.sh && \
    /venv/bin/pip3 install --no-cache-dir /libs/libCRS && \
    /venv/bin/pip3 install --no-cache-dir /libs/libMSA/python && \
    /venv/bin/pip3 install --no-cache-dir hatch && \
    /venv/bin/pip3 install --no-cache-dir /libs/libatlantis

# Copy and install package
COPY ./microservices/custom_fuzzer /custom_fuzzer
ENV USERSPACE_CUSTOM_FUZZERS_REPO_PATH=/custom_fuzzer/userspace-custom-fuzzers
RUN /venv/bin/pip3 install --no-cache-dir /custom_fuzzer/userspace-custom-fuzzers/custom_fuzzer_utils
RUN /venv/bin/pip3 install --no-cache-dir /custom_fuzzer

WORKDIR /custom_fuzzer
RUN chmod +x run.sh

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./run.sh"]