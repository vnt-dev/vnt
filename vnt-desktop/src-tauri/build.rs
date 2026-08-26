fn main() {
    let target = std::env::var("TARGET").expect("Cargo did not provide TARGET");
    println!("cargo:rustc-env=VNT_SIDECAR_TARGET={target}");

    // `cargo check` 不会执行 Tauri 的 beforeBuildCommand。为配置校验准备一个占位文件；
    // 真正打包/开发前，prepare-sidecar.mjs 会用对应目标的内核程序覆盖它。
    let extension = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let sidecar = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("Cargo did not provide CARGO_MANIFEST_DIR"),
    )
    .join("binaries")
    .join(format!("vnt2-web-{target}{extension}"));
    if !sidecar.is_file() {
        std::fs::create_dir_all(sidecar.parent().expect("sidecar path has no parent"))
            .expect("failed to create sidecar directory");
        std::fs::write(&sidecar, []).expect("failed to create sidecar placeholder");
    }
    tauri_build::build()
}
