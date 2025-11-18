FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Setup wasm-smith
RUN apt-get update && apt-get install -y \
    curl git \
    build-essential

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.87
RUN rustup install nightly && rustup default nightly

WORKDIR /app
COPY . .

# Setup wasm-tools with wasm3-rs and wabt-rs
WORKDIR /app/wasm-tools/
RUN cargo install --locked wasm-tools
