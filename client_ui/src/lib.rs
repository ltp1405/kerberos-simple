pub mod client;
pub mod config;
mod util;

use crate::config::TransportType;
use clap::{Parser, Subcommand, ValueEnum};

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
        principal: String,

        #[arg(long)]
        password: String,

        #[arg(long, default_value = "10h")]
        ticket_lifetime: String,

        #[arg(long, default_value = "6d")]
        ticket_renew_time: String,

        #[arg(short, long)]
        proxiable: bool,

        #[arg(short, long)]
        forwardable: bool,

        #[arg(short, long)]
        renewable: bool,

        #[arg(long)]
        transport: TransportType,
    },
    ListTicket,
}
