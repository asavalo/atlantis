use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/test.proto"], &["proto/"]).unwrap();
    Ok(())
}
