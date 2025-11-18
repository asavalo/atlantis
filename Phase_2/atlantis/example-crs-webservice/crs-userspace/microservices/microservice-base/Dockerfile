FROM ubuntu@sha256:ed1544e454989078f5dec1bfdabd8c5cc9c48e0705d07b678ab6ae3fb61952d2
LABEL name="microservice-base"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    curl software-properties-common && \
    apt-add-repository ppa:deadsnakes/ppa && \
    apt-get update && apt-get install -y python3.12 python3.12-dev python3.12-venv && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12 && \
    apt-get update && apt-get install -y wget unzip rsync && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

# Create venv
RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:$PATH"

# Copy necessary directories
COPY ./libs/libCRS /libs/libCRS
COPY ./libs/libMSA /libs/libMSA
COPY ./libs/libatlantis /libs/libatlantis

# Build libatlantis
RUN /venv/bin/pip3 install mypy-protobuf==3.6.0 && \
    /libs/libatlantis/build.sh && \
    /venv/bin/pip3 install --no-cache-dir /libs/libCRS && \
    /venv/bin/pip3 install --no-cache-dir /libs/libMSA/python && \
    /venv/bin/pip3 install --no-cache-dir hatch && \
    /venv/bin/pip3 install --no-cache-dir /libs/libatlantis