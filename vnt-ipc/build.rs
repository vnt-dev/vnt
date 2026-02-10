fn main() {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config
        .compile_protos(&["proto/local_ipc.proto"], &["proto"])
        .unwrap();
}
