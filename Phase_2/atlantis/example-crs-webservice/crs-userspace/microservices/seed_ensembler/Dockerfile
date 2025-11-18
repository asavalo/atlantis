FROM cruizba/ubuntu-dind@sha256:9cf8e63414de9e1536570ae6907560d4c84a682225755bc20978d949ec7e020e
LABEL name="seed_ensembler"

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    wget curl tini \
    software-properties-common \
    rsync \
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

# Create venv
RUN python3.12 -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY ./libs/libatlantis /libs/libatlantis
COPY ./libs/libCRS /libs/libCRS
COPY ./libs/libMSA /libs/libMSA
COPY ./microservices/seed_ensembler /seed_ensembler

RUN /venv/bin/pip3 install mypy-protobuf==3.6.0 && \
    /libs/libatlantis/build.sh && \
    /venv/bin/pip3 install /libs/libCRS && \
    /venv/bin/pip3 install /libs/libMSA/python && \
    /venv/bin/pip3 install hatch && \
    /venv/bin/pip3 install /libs/libatlantis && \
    /venv/bin/pip3 install /seed_ensembler/seed_ensembler

# Install the package
RUN cp /seed_ensembler/setup.py /seed_ensembler/seed_ensembler/setup.py
RUN /venv/bin/pip3 install --no-cache-dir /seed_ensembler/seed_ensembler

WORKDIR /seed_ensembler

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["./run.sh"]