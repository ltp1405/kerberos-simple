use clap::Parser;
use client_ui::cli::{
    Cli, Commands,
    Commands::{GetTicket, ListTicket},
};
use client_ui::config::AppConfig;
use client_ui::get_ticket_handler::GetTicketHandlerBuilder;
use client_ui::list_ticket_handler::ListTicketHandler;
use client_ui::send_ap_req_handler::PrintApReqHandler;
use config::ConfigError;
use kerberos::client::ap_exchange::prepare_ap_request;
use messages::Encode;
use reqwest::Url;
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let config = match AppConfig::init(
        args.config_path
            .clone()
            .unwrap_or_else(|| "cfg".to_string()),
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            match e {
                ConfigError::NotFound(msg) => println!("{}", msg),
                ConfigError::Message(msg) => println!("{}", msg),
                _ => println!("{:?}", e),
            };
            return;
        }
    };
    match args.command {
        ListTicket => {
            let handler = ListTicketHandler::default();
            let tickets = handler.list_tickets();
            for ticket in tickets {
                let sname = ticket.sname();
                let realm = ticket.realm();
                println!("Ticket from {:?} - {:?}", ticket.sname(), ticket.realm());
            }
        }
        GetTicket {
            target_realm,
            password,
            ticket_lifetime,
            ticket_renew_time,
            proxiable,
            forwardable,
            renewable,
            target_principal,
            transport,
            as_server_address,
            tgs_server_address,
        } => {
            let client = GetTicketHandlerBuilder::default()
                .cache_location(config.cache_location.unwrap_or_else(|| PathBuf::from("./")))
                .renewable(renewable)
                .as_sender(as_server_address)
                .tgs_sender(tgs_server_address)
                .ticket_lifetime(ticket_lifetime.into())
                .transport_type(transport)
                .realm(config.realm.clone())
                .key(password.or(config.key))
                .server_name(Some(target_principal))
                .as_receiver(Some(config.address))
                .tgs_receiver(Some(config.address))
                .ticket_renew_time(Some(ticket_renew_time))
                .server_realm(Some(target_realm))
                .name(config.name.clone())
                .build()
                .unwrap();
            client.handle().await.unwrap();
        }
        Commands::SendApReq { server_address } => {
            let client = PrintApReqHandler {
                name: config.name.clone(),
                realm: config.realm.clone(),
                cache_location: config.cache_location.unwrap_or_else(|| PathBuf::from("./")),
            };
            let req = prepare_ap_request(&client, false, None)
                .unwrap()
                .to_der()
                .unwrap();
            let http_client = reqwest::Client::new();
            let res = http_client
                .post(Url::parse(&format!("http://{}/ap_req", server_address)).unwrap())
                .body(req)
                .send()
                .await
                .unwrap();
        }
    }
}
