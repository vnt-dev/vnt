fn main() {
    let mut config = prost_build::Config::new();

    match protoc_bin_vendored::protoc_bin_path() {
        Ok(protoc_path) => {
            config.protoc_executable(protoc_path);
        }
        Err(error) => {
            println!(
                "cargo:warning=vendored protoc unavailable ({error:?}); falling back to protoc from PATH"
            );
        }
    }

    config.protoc_arg("--experimental_allow_proto3_optional");
    config
        .compile_protos(&["proto/local_ipc.proto"], &["proto"])
        .unwrap();
}
