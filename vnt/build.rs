use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        cipher: {
            any(feature = "aes_gcm",
            feature = "chacha20_poly1305",
            feature = "server_encrypt",
            feature = "aes_cbc",
            feature = "aes_ecb",
            feature = "sm4_cbc"
        )},
    }

    std::fs::create_dir_all("src/proto").unwrap();
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir("src/proto")
        .inputs(&["proto/message.proto"])
        .include("proto")
        // .customize(
        //     protobuf_codegen::Customize::default()
        //         .tokio_bytes(true)
        // )
        .run()
        .expect("Codegen failed.");
}
