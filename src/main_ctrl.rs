use clap::{Parser, Subcommand};
use vnt_ipc::message::ipc_request::IpcCmd;

/// 操作vnt进程
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
    /// 核心进程控制端口
    #[clap(short, long)]
    port: Option<u16>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 输出当前程序信息
    Info,
    /// 输出客户端ip列表
    Ips,
    /// 输出客户端信息列表
    #[command(alias = "list")]
    Clients,
    /// 输出IP路由信息
    Route,
}

#[tokio::main]
pub async fn main() {
    let args = Args::parse();
    let port = args.port;
    let cmd = match args.command {
        Commands::Info => IpcCmd::AppInfo(Default::default()),

        Commands::Ips => IpcCmd::ClientIps(Default::default()),
        Commands::Clients => IpcCmd::ClientList(Default::default()),
        Commands::Route => IpcCmd::AllRoute(Default::default()),
    };
    if let Err(e) = vnt_ipc::client::run_client(cmd, port).await {
        eprintln!("{:?}", e);
    }
}
