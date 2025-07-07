#!/bin/bash

# VNT 项目 aarch64 交叉编译脚本
# 使用 Sigmastar GCC 10.2.1 交叉编译工具链

set -e

# 颜色输出
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 显示用法
usage() {
    echo "用法: $0 [选项] [包名]"
    echo ""
    echo "选项:"
    echo "  -h, --help     显示此帮助信息"
    echo "  -c, --clean    编译前清理缓存"
    echo ""
    echo "包名 (可选):"
    echo "  vn-link-cli    只编译 vn-link-cli"
    echo "  vnt-cli        只编译 vnt-cli"
    echo "  不指定         编译所有包"
    echo ""
    echo "示例:"
    echo "  $0                    # 编译所有包"
    echo "  $0 vn-link-cli        # 只编译 vn-link-cli"
    echo "  $0 -c vnt-cli         # 清理后编译 vnt-cli"
}

# 检查依赖
check_dependencies() {
    local toolchain_path="/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu"

    if [ ! -d "$toolchain_path" ]; then
        echo -e "${RED}错误: 交叉编译工具链不存在: $toolchain_path${NC}"
        exit 1
    fi

    if [ ! -f "/usr/lib/llvm-10/lib/libclang.so" ]; then
        echo -e "${YELLOW}警告: libclang 未找到，正在安装...${NC}"
        sudo apt update && sudo apt install -y libclang-dev clang
    fi
}

# 设置环境变量
setup_env() {
    export LIBCLANG_PATH="/usr/lib/llvm-10/lib"
    export CC_aarch64_unknown_linux_gnu="/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-gcc"
    export AR_aarch64_unknown_linux_gnu="/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-ar"
    export BINDGEN_EXTRA_CLANG_ARGS_aarch64_unknown_linux_gnu="--sysroot=/home/zkteco/gcc-10.2.1-20210303-sigmastar-glibc-x86_64_aarch64-linux-gnu/aarch64-linux-gnu/libc"
}

# 编译函数
build_package() {
    local package=$1
    echo -e "${GREEN}正在编译 $package...${NC}"
    cargo build --package "$package" --release --target aarch64-unknown-linux-gnu

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}$package 编译成功！${NC}"
        ls -la "target/aarch64-unknown-linux-gnu/release/$package"
        file "target/aarch64-unknown-linux-gnu/release/$package"
    else
        echo -e "${RED}$package 编译失败！${NC}"
        exit 1
    fi
}

# 解析参数
CLEAN=false
PACKAGE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        vn-link-cli|vnt-cli)
            PACKAGE=$1
            shift
            ;;
        *)
            echo -e "${RED}未知参数: $1${NC}"
            usage
            exit 1
            ;;
    esac
done

# 主程序
echo -e "${GREEN}VNT 项目 aarch64 交叉编译${NC}"

check_dependencies
setup_env

if [ "$CLEAN" = true ]; then
    echo -e "${GREEN}清理构建缓存...${NC}"
    cargo clean
fi

if [ -n "$PACKAGE" ]; then
    build_package "$PACKAGE"
else
    echo -e "${GREEN}编译所有包...${NC}"
    build_package "vn-link-cli"
    echo ""
    build_package "vnt-cli"
fi

echo -e "${GREEN}编译完成！${NC}"
