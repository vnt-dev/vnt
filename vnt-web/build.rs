//! 构建 vnt-web 前自动构建前端 UI（vnt-web/ui -> vnt-web/static）。
//!
//! - 前端源码（ui/src 等）比 static 产物新、或产物缺失时，调用 pnpm 构建
//! - 产物已是最新则跳过，不拖慢增量编译
//! - 找不到 pnpm 时：已有产物则告警并沿用；没有产物则报错并给出指引
//! - 设置环境变量 VNT_WEB_SKIP_UI_BUILD=1 可完全跳过前端构建

use std::error::Error;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::SystemTime;

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let manifest_dir = Path::new(&manifest_dir);
    let ui_dir = manifest_dir.join("ui");
    let static_dir = manifest_dir.join("static");
    let workspace_root = manifest_dir
        .parent()
        .ok_or_else(|| io::Error::other("vnt-web manifest directory has no parent"))?;

    // UI 源码变化时重新运行本脚本
    println!("cargo:rerun-if-changed={}", ui_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ui_dir.join("index.html").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ui_dir.join("vite.config.js").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ui_dir.join("package.json").display()
    );
    // 产物被删除时也要重新运行
    println!(
        "cargo:rerun-if-changed={}",
        static_dir.join("index.html").display()
    );
    println!("cargo:rerun-if-env-changed=VNT_WEB_SKIP_UI_BUILD");

    if std::env::var("VNT_WEB_SKIP_UI_BUILD").is_ok() {
        ensure_static_placeholder(&static_dir)?;
        return Ok(());
    }

    if static_is_fresh(&ui_dir, &static_dir) {
        return Ok(());
    }

    let Some(pnpm) = find_pnpm() else {
        if static_dir.join("index.html").is_file() {
            println!(
                "cargo:warning=未找到 pnpm，沿用 vnt-web/static 中已有的前端产物（可能不是最新）"
            );
            return Ok(());
        }
        return Err(io::Error::other(
            "未找到 pnpm 且 vnt-web/static 没有前端产物。\n\
             请安装 Node.js 与 pnpm 后重新构建（cargo 会自动完成前端构建），\n\
             或从发布包中获取 static 目录放入 vnt-web/。",
        )
        .into());
    };

    if !ui_dir.join("node_modules").is_dir() {
        // ui 依赖使用 workspace catalog，必须在仓库根目录安装
        run_command(pnpm, &["install", "--frozen-lockfile"], workspace_root)?;
    }
    run_command(pnpm, &["--filter", "vnt-web-ui", "build"], workspace_root)?;
    Ok(())
}

/// pnpm 命令名（Windows 上是 pnpm.cmd，由 cmd.exe 执行）
fn find_pnpm() -> Option<&'static str> {
    let candidates: &[&str] = if cfg!(windows) {
        &["pnpm.cmd", "pnpm"]
    } else {
        &["pnpm"]
    };
    candidates
        .iter()
        .copied()
        .find(|cmd| Command::new(cmd).arg("--version").output().is_ok())
}

fn run_command(program: &str, args: &[&str], dir: &Path) -> io::Result<()> {
    println!(
        "cargo:warning=执行前端构建: {} {} ({})",
        program,
        args.join(" "),
        dir.display()
    );
    let status = Command::new(program)
        .args(args)
        .current_dir(dir)
        .status()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("执行 {program} 失败（目录 {}）：{error}", dir.display()),
            )
        })?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "前端构建失败: {} {} (exit: {:?})",
            program,
            args.join(" "),
            status.code()
        )));
    }
    Ok(())
}

/// static 产物是否比 UI 源码新
fn static_is_fresh(ui_dir: &Path, static_dir: &Path) -> bool {
    let Ok(built_at) = std::fs::metadata(static_dir.join("index.html")).and_then(|m| m.modified())
    else {
        return false;
    };
    newest_mtime(&ui_dir.join("src")).is_none_or(|t| t <= built_at)
}

fn newest_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(m) = entry.metadata().and_then(|m| m.modified()) {
                newest = Some(newest.map_or(m, |n| n.max(m)));
            }
        }
    }
    newest
}

/// 跳过构建时保证 static/ 存在，使 rust_embed 可以编译
fn ensure_static_placeholder(static_dir: &Path) -> io::Result<()> {
    if static_dir.join("index.html").is_file() {
        return Ok(());
    }
    println!("cargo:warning=VNT_WEB_SKIP_UI_BUILD 已设置且 static 为空，写入占位页面");
    std::fs::create_dir_all(static_dir)?;
    std::fs::write(
        static_dir.join("index.html"),
        "<!doctype html><html><body><p>VNT Web UI 未构建。请安装 pnpm 后重新执行 cargo build，\
         或取消 VNT_WEB_SKIP_UI_BUILD。</p></body></html>",
    )?;
    Ok(())
}
