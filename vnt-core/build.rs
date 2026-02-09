fn main() {
    let mut config = prost_build::Config::new();
    config.protoc_arg("--experimental_allow_proto3_optional");
    config
        .compile_protos(
            &[
                "proto/control_message.proto",
                "proto/rpc.proto",
                "proto/client.proto",
                "proto/fec.proto",
            ],
            &["proto"],
        )
        .unwrap();
}
