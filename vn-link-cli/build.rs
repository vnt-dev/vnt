
fn main() {
    // 配置 thunk-rs 来链接 Windows 7 兼容库，并自动设置链接参数
    #[cfg(target_os = "windows")] 
    thunk::thunk();
}
