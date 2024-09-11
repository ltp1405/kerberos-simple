use clap::Parser;
use client_ui::client::AppConfig;
use client_ui::Cli;
use config::ConfigError;

fn main() {
    let config = match AppConfig::init() {
        Ok(cfg) => cfg,
        Err(e) => {
            match e {
                ConfigError::NotFound(msg) => println!("{}", msg),
                ConfigError::Message(msg) => println!("{}", msg),
                _ => println!("Internal erro"),
            };
            return;
        }
    };
    let args = Cli::parse();
    match args.command {
        client_ui::Commands::ListTicket => todo!(),
        client_ui::Commands::GetTicket {
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
