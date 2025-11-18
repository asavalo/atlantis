use std::io::Result;

fn main() -> Result<()> {
    let proto_dir = std::env::var("PROTO_DIR")
        .expect("PROTO_DIR is not set");

    let mut proto_file_1 = proto_dir.clone();
    proto_file_1.push_str("/coverage-service.proto");
    let mut proto_file_2 = proto_dir.clone();
    proto_file_2.push_str("/fuzzer-manager.proto");
    let mut proto_file_3 = proto_dir.clone();
    proto_file_3.push_str("/harness-builder.proto");

    prost_build::compile_protos(&[proto_file_1, proto_file_2, proto_file_3], &[proto_dir])
        .expect("coverage_service: failed to compile .proto files");

    Ok(())
}
