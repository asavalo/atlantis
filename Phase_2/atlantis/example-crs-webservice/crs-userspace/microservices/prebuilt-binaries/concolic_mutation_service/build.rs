pub fn main() {
    tonic_build::compile_protos("proto/mutation_service.proto").unwrap();
}
