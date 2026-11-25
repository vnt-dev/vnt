use clap::{Parser, Subcommand};
use vnt_ipc::message::StopCmd;
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
    /// 正常停止 CLI 实例，需要在两端设置 VNT_IPC_STOP_TOKEN
    Stop,
}

#[tokio::main]
pub async fn main() {
    let args = Args::parse();
    let port = args.port;
    let stopping = matches!(args.command, Commands::Stop);
    let cmd = match args.command {
        Commands::Info => IpcCmd::AppInfo(Default::default()),

        Commands::Ips => IpcCmd::ClientIps(Default::default()),
        Commands::Clients => IpcCmd::ClientList(Default::default()),
        Commands::Route => IpcCmd::AllRoute(Default::default()),
        Commands::Stop => {
            let token = match vnt_ipc::stop_token() {
                Ok(Some(token)) => token,
                Ok(None) => {
                    eprintln!("Set {} before requesting a stop.", vnt_ipc::STOP_TOKEN_ENV);
                    std::process::exit(1);
                }
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            };
            IpcCmd::Stop(StopCmd { token })
        }
    };
    if let Err(e) = vnt_ipc::client::run_client(cmd, port).await {
        eprintln!("{:?}", e);
        if stopping {
            std::process::exit(1);
        }
    }
}
