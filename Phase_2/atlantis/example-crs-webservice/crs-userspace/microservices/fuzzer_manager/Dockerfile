ARG VERSION="latest"
FROM ghcr.io/aixcc-finals/base-runner:v1.3.0
LABEL name="fuzzer_manager"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y wget unzip tini libzmq3-dev && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

# Create venv
RUN python3.10 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy necessary directories
COPY ./libs/libCRS /libs/libCRS
COPY ./libs/libMSA /libs/libMSA
COPY ./libs/libatlantis /libs/libatlantis
COPY ./microservices/fuzzer_manager /fuzzer_manager

# Build libatlantis
RUN /venv/bin/pip3 install --no-cache-dir mypy-protobuf==3.6.0 && \
    /libs/libatlantis/build.sh && \
    /venv/bin/pip3 install --no-cache-dir /libs/libCRS && \
    /venv/bin/pip3 install --no-cache-dir /libs/libMSA/python && \
    /venv/bin/pip3 install --no-cache-dir hatch && \
    /venv/bin/pip3 install --no-cache-dir /libs/libatlantis && \
    /venv/bin/pip3 install --no-cache-dir /fuzzer_manager

WORKDIR /fuzzer_manager

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/venv/bin/python3", "-m", "fuzzer_manager"]
