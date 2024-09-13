use kerberos_infra::server::{
    database::{
        postgres::{schemas::Krb5DbSchemaV1, PgDbSettings},
        DbSettings,
    },
    load_server_from_dir,
    types::Protocol,
    Builder, Server,
};
use receivers::{NpglAsReqHandler, NpglTgsReqHandler};
use sqlx::PgPool;

#[derive(Clone)]
pub struct NpglKdcSrcConfig {
    pub realm: String,
    pub sname: String,
    pub require_preauth: bool,
}

pub struct NpglKdcSrv {
    server: Server<PgPool>,
}

impl NpglKdcSrv {
    pub fn new(server: Server<PgPool>) -> Self {
        Self { server }
    }

    pub async fn run_until_stopped(&mut self) -> Result<(), &'static str> {
        let result = self.server.prepare_and_run().await;

        match result {
            Ok(_) => Ok(()),
            Err(_) => Err("Server stopped unexpectedly"),
        }
    }
}

pub fn start_kdc_srv_from_dir() -> NpglKdcSrv {
    let config = NpglKdcSrcConfig {
        realm: "EXAMPLE.COM".to_string(),
        sname: "krbtgt".to_string(),
        require_preauth: false,
    };

    let settings = PgDbSettings::load_from_dir();

    let server = load_server_from_dir::<PgPool>()
        .unwrap()
        .set_as_receiver(NpglAsReqHandler::new(config.clone()))
        .set_tgs_receiver(NpglTgsReqHandler::new(config))
        .use_postgres(settings, Krb5DbSchemaV1::boxed())
        .build(Protocol::Tcp)
        .unwrap();

    NpglKdcSrv::new(server)
}

mod receivers;
mod types;
