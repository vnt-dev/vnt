# VNT 项目 aarch64 交叉编译指南

本文档说明如何为 aarch64 架构交叉编译 VNT 项目。

## 前提条件

1. **交叉编译工具链**: 确保 Sigmastar GCC 10.2.1 交叉编译工具链已安装在以下路径：
   ```
   /home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu
   ```

2. **系统依赖**: 需要安装 `libclang-dev` 和 `clang` (lwip-rs 的 bindgen 需要)：
   ```bash
   sudo apt update && sudo apt install -y libclang-dev clang
   ```

## 快速开始

使用提供的构建脚本：

```bash
# 编译所有项目
./build-aarch64.sh

# 只编译 vn-link-cli
./build-aarch64.sh vn-link-cli

# 只编译 vnt-cli
./build-aarch64.sh vnt-cli

# 清理后编译
./build-aarch64.sh -c

# 查看帮助
./build-aarch64.sh -h
```

## 手动编译

如果您想手动编译，可以使用以下命令：

```bash
# 设置环境变量
export LIBCLANG_PATH="/usr/lib/llvm-10/lib"
export CC_aarch64_unknown_linux_gnu="/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc"
export AR_aarch64_unknown_linux_gnu="/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-ar"
export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="--sysroot=/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/libc"

# 编译 vn-link-cli
cargo build --package vn-link-cli --release --target aarch64-unknown-linux-gnu

# 编译 vnt-cli
cargo build --package vnt-cli --release --target aarch64-unknown-linux-gnu
```

## 配置文件

项目的 `.cargo/config.toml` 文件已经配置了基本的交叉编译设置：

```toml
[target.aarch64-unknown-linux-gnu]
linker = "/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc"

[env]
CC_aarch64_unknown_linux_gnu = "/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc"
AR_aarch64_unknown_linux_gnu = "/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-ar"
```

## 输出文件

编译成功后，生成的二进制文件位于：

- `target/aarch64-unknown-linux-gnu/release/vn-link-cli`
- `target/aarch64-unknown-linux-gnu/release/vnt-cli`

## 故障排除

### 1. lwip-rs 编译失败

`lwip-rs` 使用 `bindgen` 生成 C 绑定，需要 `libclang`：

```bash
sudo apt update && sudo apt install -y libclang-dev clang
```

### 2. 交叉编译工具链问题

确保交叉编译工具链路径正确：

```bash
ls -la /home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc
```

### 3. 清理构建缓存

如果遇到编译错误，尝试清理缓存：

```bash
./build-aarch64.sh -c
# 或者
cargo clean
```

## 验证编译结果

使用 `file` 命令验证生成的二进制文件：

```bash
file target/aarch64-unknown-linux-gnu/release/vn-link-cli
file target/aarch64-unknown-linux-gnu/release/vnt-cli
```

应该显示类似以下输出：
```
target/aarch64-unknown-linux-gnu/release/vn-link-cli: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, BuildID[sha1]=..., for GNU/Linux 3.7.0, not stripped
```
