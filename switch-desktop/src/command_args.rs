use clap::{Arg, ArgAction, Command};
use clap::builder::BoolishValueParser;
use crate::i18n::*;

fn common() -> Command {
    Command::new("switch-desktop")
        .about(switch_about())
        // .version(switch_version())
        .subcommand_required(true)
        .arg_required_else_help(true)
        // .author(switch_author())
        .override_usage(switch_usage())
        .subcommand(
            Command::new("start")
                .about(switch_start_about())
                .arg(
                    Arg::new("token")
                        .long("token")
                        .help(switch_token_help())
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::new("name")
                        .long("name")
                        .help(switch_name_help())
                        .action(ArgAction::Set)
                )
                .arg(
                    Arg::new("device_id")
                        .long("device-id")
                        .help(switch_device_id_help())
                        .action(ArgAction::Set)
                ).arg(
                Arg::new("server")
                    .long("server")
                    .help(switch_server_help())
                    .action(ArgAction::Set)
            ).arg(
                Arg::new("nat_test_server")
                    .long("nat-test-server")
                    .help(switch_nat_test_server_help())
                    .action(ArgAction::Set)
            ).arg(
                Arg::new("log")
                    .long("log")
                    .help(switch_log_help())
                    .action(ArgAction::SetTrue)
                    .value_parser(BoolishValueParser::new()),
            ).arg(
                Arg::new("tap")
                    .long("tap")
                    .help(switch_tap_help())
                    .action(ArgAction::SetTrue),
            ).arg(
                Arg::new("in_ip")
                    .long("in-ip")
                    .help(switch_in_ip_help())
                    .action(ArgAction::Append)
                    .num_args(1..),
            ).arg(
                Arg::new("out_ip")
                    .long("out-ip")
                    .help(switch_out_ip_help())
                    .action(ArgAction::Append)
            ).arg(
                Arg::new("password")
                    .long("password")
                    .help(switch_password_help())
                    .action(ArgAction::Set)
            ).arg(
                Arg::new("config")
                    .long("config")
                    .help(switch_config_help())
                    .action(ArgAction::Set)
            )
            ,
        ).subcommand(
        Command::new("stop")
            .about(switch_stop_about()))
        .subcommand(
            Command::new("route")
                .about(switch_route_about()))
        .subcommand(Command::new("list")
            .about(switch_list_about()).arg(
            Arg::new("all")
                .long("all")
                .short('a')
                .help(switch_list_all_help())
                .action(ArgAction::SetTrue)
                .value_parser(BoolishValueParser::new()), ))
        .subcommand(Command::new("status")
            .about(switch_status_about()))
}

pub fn check() -> bool {
    #[cfg(windows)]
        let cmd = common().subcommand(Command::new("install")
        .about(switch_install_about())
        .arg(
            Arg::new("path")
                .long("path")
                .help(switch_path_help())
                .action(ArgAction::Set)
                .num_args(1..))
        .arg(
            Arg::new("auto")
                .long("auto")
                .help(switch_auto_help())
                .action(ArgAction::SetTrue)
                .value_parser(BoolishValueParser::new()), ))
        .subcommand(Command::new("uninstall")
            .about(switch_uninstall_about()))
        .subcommand(Command::new("config")
            .about(switch_config_about())
            .arg(
                Arg::new("auto")
                    .long("auto")
                    .help(switch_auto_help())
                    .action(ArgAction::SetTrue)
                    .value_parser(BoolishValueParser::new()), ));
    #[cfg(any(unix))]
        let cmd = common();
    match cmd.try_get_matches() {
        Ok(_) => {
            true
        }
        Err(e) => {
            println!("{}", e);
            false
        }
    }
}

