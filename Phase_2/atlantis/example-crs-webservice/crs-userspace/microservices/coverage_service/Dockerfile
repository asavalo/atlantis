FROM cruizba/ubuntu-dind@sha256:9cf8e63414de9e1536570ae6907560d4c84a682225755bc20978d949ec7e020e

ENV TZ=US \
    DEBIAN_FRONTEND=noninteractive

# Install Rust
RUN curl https://sh.rustup.rs -sSf | bash -s -- -y --default-toolchain 1.87
ENV PATH="/root/.cargo/bin:${PATH}"

# Install Protobuf compiler
RUN apt-get update && apt-get install -y wget unzip && \
    wget https://github.com/protocolbuffers/protobuf/releases/download/v29.1/protoc-29.1-linux-x86_64.zip -O /tmp/protoc.zip && \
    mkdir -p /tmp/protoc && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm /tmp/protoc.zip

RUN apt-get install -y rsync
  
WORKDIR /coverage_service
COPY ./microservices/coverage_service /coverage_service

CMD ["./run.sh"]