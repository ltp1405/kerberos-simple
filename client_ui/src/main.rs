use clap::Parser;
use client_ui::config::{AppConfig, TransportType};
use client_ui::Cli;
use client_ui::Commands::{ChooseTransportLayer, GetTicket, ListTicket};
use config::ConfigError;

fn main() {
    let mut config = match AppConfig::init() {
        Ok(cfg) => cfg,
        Err(e) => {
            match e {
                ConfigError::NotFound(msg) => println!("{}", msg),
                ConfigError::Message(msg) => println!("{}", msg),
                _ => println!("Internal error"),
            };
            return;
        }
    };
    let args = Cli::parse();
    match args.command {
        ListTicket => todo!(),
        ChooseTransportLayer { transport_layer } => {
            config.tranport_type = match transport_layer.to_lowercase().as_str() {
                "tcp" => TransportType::Tcp,
                "udp" => TransportType::Udp,
                _ => {
                    println!("Invalid transport layer");
                    return;
                }
            };
        }
        GetTicket {
            principal,
            password,
            ticket_lifetime,
            ticket_renew_time,
            proxiable,
            forwardable,
            renewable,
        } => {
            todo!()
        }
    }
}
