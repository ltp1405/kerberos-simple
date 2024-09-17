use clap::{Parser, Subcommand};
use humantime::Duration;
use crate::config::TransportType;

#[derive(Parser)]
pub struct Cli {
    pub config_path: Option<String>,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    GetTicket {
        #[arg(long)]
        target_principal: String,

        #[arg(long)]
        target_realm: String,

        #[arg(long)]
        password: Option<String>,

        #[arg(long, default_value = "10h")]
        ticket_lifetime: Duration,

        #[arg(long, default_value = "2020-01-01T00:00:00Z")]
        ticket_renew_time: humantime::Timestamp,

        #[arg(short, long)]
        proxiable: bool,

        #[arg(short, long)]
        forwardable: bool,

        #[arg(short, long)]
        renewable: bool,

        #[arg(long, default_value = "tcp")]
        transport: TransportType,

        #[arg(long)]
        as_server_address: std::net::SocketAddr,

        #[arg(long)]
        tgs_server_address: std::net::SocketAddr,
    },
    ListTicket,
    SendApReq {
        #[arg(long)]
        server_address: std::net::SocketAddr,
    },
}
