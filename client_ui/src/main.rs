use clap::Parser;
use client_ui::Cli;

fn main() {
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
        } => todo!(),
    }
}
