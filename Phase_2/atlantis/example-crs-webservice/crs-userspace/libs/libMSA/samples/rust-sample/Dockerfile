FROM rust

RUN apt-get update && apt-get install -y protobuf-compiler

WORKDIR /usr/src/rust-sample

COPY src /usr/src/rust-sample/src
COPY build.rs /usr/src/rust-sample/build.rs
COPY Cargo.toml /usr/src/rust-sample/Cargo.toml
COPY proto /usr/src/rust-sample/proto
COPY libmsa /usr/src/rust-sample/libmsa

RUN cargo build --release

CMD ["/usr/src/rust-sample/target/release/rust-sample", "rust_sample", "3"]