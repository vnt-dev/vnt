fn main() {
    let protoc_path =
        protoc_bin_vendored::protoc_bin_path().expect("failed to find vendored protoc");

    let mut config = prost_build::Config::new();

    config.protoc_executable(protoc_path);
    config.protoc_arg("--experimental_allow_proto3_optional");
    config
        .compile_protos(&["proto/local_ipc.proto"], &["proto"])
        .unwrap();
}
