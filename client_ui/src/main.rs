use clap::Parser;
use client_ui::cli::{
    Cli, Commands,
    Commands::{GetTicket, ListTicket},
};
use client_ui::config::AppConfig;
use client_ui::get_ticket_handler::GetTicketHandlerBuilder;
use client_ui::list_ticket_handler::ListTicketHandler;
use client_ui::send_ap_req_handler::SendApReqHandler;
use config::ConfigError;
use kerberos::client::ap_exchange::prepare_ap_request;
use kerberos::client::client_env::ClientEnv;
use messages::{ApRep, Decode, EncApRepPart, Encode};
use reqwest::Url;
use std::collections::HashMap;
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
                println!("Ticket from {:?} - {:?}", ticket.sname(), ticket.realm());
            }
        }
        GetTicket {
            target_realm,
            password,
            ticket_lifetime,
            ticket_renew_time,
            proxiable: _,
            forwardable: _,
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
            let client = SendApReqHandler {
                name: config.name.clone(),
                realm: config.realm.clone(),
                cache_location: config.cache_location.unwrap_or_else(|| PathBuf::from("./")),
            };
            let req = prepare_ap_request(&client, false, None)
                .unwrap()
                .to_der()
                .unwrap();
            let http_client = reqwest::Client::new();
            let mut data = HashMap::new();
            data.insert("ticket", hex::encode(req));
            let res = http_client
                .post(Url::parse(&format!("http://{}/authenticate", server_address)).unwrap())
                .json(&data)
                .send()
                .await
                .unwrap();

            let res = res.bytes().await.unwrap();
            match ApRep::from_der(&res) {
                Ok(ap_rep) => {
                    let tgs_rep = client.get_tgs_reply_enc_part().unwrap();
                    let session_key = tgs_rep.key().keyvalue().as_bytes();
                    let ap_rep_decrypted = EncApRepPart::from_der(
                        client
                            .get_crypto(*client.get_tgs_reply_enc_part().unwrap().key().keytype())
                            .unwrap()
                            .decrypt(ap_rep.enc_part().cipher().as_ref(), session_key)
                            .unwrap()
                            .as_slice(),
                    )
                    .unwrap();
                    let seq_number = *ap_rep_decrypted.seq_number().unwrap();
                    let res = http_client
                        .get(
                            Url::parse(&format!("http://{}/users/{}", server_address, config.name))
                                .unwrap(),
                        )
                        .query(&[
                            ("realm", "MYREALM.COM"),
                            ("sequence", seq_number.to_string().as_str()),
                        ])
                        .send()
                        .await
                        .unwrap();
                    let res = res.text().await.unwrap();
                    let res_json: serde_json::Value = serde_json::from_str(&res).unwrap();
                    println!("{}", serde_json::to_string_pretty(&res_json).unwrap());
                }
                Err(e) => {
                    println!("Failed to parse AP_REP: {:?}", e);
                }
            }
        }
    }
}
