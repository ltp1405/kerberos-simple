use clap::Parser;
use client_ui::client::Client;
use client_ui::config::{AppConfig, TransportType};
use client_ui::Cli;
use client_ui::Commands::{ChooseTransportLayer, GetTicket, ListTicket};
use config::ConfigError;
use kerberos::client::as_exchange::prepare_as_request;
use messages::basic_types::KerberosTime;
use messages::{AsRep, Decode, Encode};

#[tokio::main]
async fn main() {
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
        ListTicket => {
            let client =
                Client::new(false, "server".to_string(), config.realm, config.address).unwrap();
            println!("List ticket: ");
            println!("{:#?}", client.list_tickets());
        }
        ChooseTransportLayer { transport_layer } => {
            config.transport_type = match transport_layer.to_lowercase().as_str() {
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
            let mut client =
                Client::new(renewable, principal, config.realm, config.address).unwrap();
            let as_req = prepare_as_request(
                &client,
                Some(humantime::parse_duration(ticket_lifetime.as_str()).unwrap()),
                None,
                match renewable {
                    true => Some(
                        KerberosTime::from_unix_duration(
                            humantime::parse_duration(ticket_renew_time.as_str()).unwrap(),
                        )
                        .unwrap(),
                    ),
                    false => None,
                },
            )
            .unwrap();
            let response = client
                .sender
                .send(as_req.to_der().unwrap().as_slice())
                .await
                .expect("failed to send");
            let as_rep = AsRep::from_der(response.as_slice()).unwrap();
            println!("{:?}", as_rep);
        }
    }
}
