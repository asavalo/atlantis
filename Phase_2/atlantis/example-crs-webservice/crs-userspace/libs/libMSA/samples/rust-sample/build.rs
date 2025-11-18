use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &["proto/message_one.proto", "proto/message_two.proto"],
        &["proto/"],
    )
    .unwrap();
    Ok(())
}
