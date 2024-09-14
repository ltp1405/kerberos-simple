use clap::Parser;
use client_ui::client::Client;
use client_ui::config::{AppConfig, TransportType};
use client_ui::Cli;
use client_ui::Commands::{GetTicket, ListTicket};
use config::ConfigError;
use kerberos::client::as_exchange::{prepare_as_request, receive_as_response};
use kerberos::client::tgs_exchange::prepare_tgs_request;
use messages::basic_types::KerberosTime;
use messages::{AsRep, Decode, Encode};
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let mut config = match AppConfig::init(
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
            let client = Client::new(config, false, None, None, None, None, PathBuf::from("./"))
                .expect("failed to create client");
            println!("List ticket: ");
            println!("{:#?}", client.list_tickets());
        }
        GetTicket {
            principal,
            password,
            ticket_lifetime,
            ticket_renew_time,
            proxiable,
            forwardable,
            renewable,
            transport,
        } => {
            match transport {
                TransportType::Tcp => {
                    config.transport_type = Some(TransportType::Tcp);
                }
                TransportType::Udp => {
                    config.transport_type = Some(TransportType::Udp);
                }
            }
            let mut client = Client::new(
                config,
                true,
                Some(principal),
                Some(password),
                None,
                None,
                PathBuf::from("./"),
            )
            .expect("failed to create client");
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
                .as_mut()
                .unwrap()
                .send(as_req.to_der().unwrap().as_slice())
                .await
                .expect("failed to send");
            let as_rep = AsRep::from_der(response.as_slice()).unwrap();
            println!("{:?}", as_rep);
            let ok = receive_as_response(&client, &as_req, &as_rep);
            match ok {
                Ok(_) => {
                    println!("Success");
                }
                Err(e) => {
                    println!("Failed: {:?}", e);
                }
            }

            let tgs_req = prepare_tgs_request(&client).unwrap();
            let response = client
                .sender
                .as_mut()
                .unwrap()
                .send(tgs_req.to_der().unwrap().as_slice())
                .await
                .expect("failed to send");
            let as_rep = AsRep::from_der(response.as_slice()).unwrap();
            let ok = receive_as_response(&client, &as_req, &as_rep);
            match ok {
                Ok(_) => {
                    println!("Success");
                }
                Err(e) => {
                    println!("Failed: {:?}", e);
                }
            }
        }
    }
}
