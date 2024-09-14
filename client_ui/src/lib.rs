pub mod client;
pub mod config;
mod util;

use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct Cli {
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
    },
    ListTicket,
    ChooseTransportLayer {
        #[arg(long)]
        transport_layer: String,
    },
}
