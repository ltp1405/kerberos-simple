use async_trait::async_trait;
use kerberos_infra::server::{
    database::{
        postgres::{schemas::Krb5DbSchemaV1, PgDbSettings},
        DbSettings,
    },
    load_server, load_server_from_dir,
    types::Protocol,
    Builder, Server,
};
use receivers::{NpglAsReqHandler, NpglTgsReqHandler};
use sqlx::PgPool;

use super::{
    configs::{AuthenticationServiceConfig, TicketGrantingServiceConfig},
    KdcSrvError, Listen,
};

pub struct NpglKdcSrv {
    server: Server<PgPool>,
}

impl NpglKdcSrv {
    pub fn new(server: Server<PgPool>) -> Self {
        Self { server }
    }
}

#[async_trait]
impl Listen for NpglKdcSrv {
    async fn listen(&mut self) -> Result<(), KdcSrvError> {
        self.server
            .prepare_and_run()
            .await
            .map_err(KdcSrvError::Unexpected)
    }

    /// Load the KDC server from the default directory of the current working directory:
    /// + For the database settings, it will load from the "database" directory
    /// + For the server settings, it will load from the "server" directory
    ///
    /// Each directory contains 3 files:
    /// + base.yaml: the base configuration file
    /// + local.yaml: the local configuration file
    /// + prod.yaml: the production configuration file
    ///
    /// base.yaml of the database directory contains the following:
    /// ```yaml
    /// postgres:
    ///  host: "localhost"
    ///  port: 5455
    ///  username: "postgres"
    ///  password: "password"
    ///  name: "kerberos"
    ///
    /// ```
    /// local.yaml and prod.yaml may override the base.yaml and add additional fields:
    /// ```yaml
    /// postgres:
    ///  require_ssl: false
    /// ```
    ///
    /// base.yaml of the server directory contains 3 yaml documents for base, local, and prod configurations
    /// ```yaml
    /// host:
    ///  protocol: "tcp" # or "udp"
    ///  as_port: 88
    ///  tgs_port: 89
    ///  host: "localhost"
    /// cache:
    ///  capacity: 1000
    ///  ttl: 3600 # in seconds
    /// ```
    fn load_from_dir(
        as_config: AuthenticationServiceConfig,
        tgs_config: TicketGrantingServiceConfig,
    ) -> Result<Self, KdcSrvError> {
        let settings = PgDbSettings::load_from_dir();

        let server = load_server_from_dir::<PgPool>()
            .unwrap()
            .set_as_receiver(NpglAsReqHandler::new(as_config))
            .set_tgs_receiver(NpglTgsReqHandler::new(tgs_config))
            .use_postgres(settings, Krb5DbSchemaV1::boxed())
            .build(Protocol::Tcp)
            .unwrap();

        Ok(NpglKdcSrv::new(server))
    }

    /// Load the KDC server from the specified directory rooted at the current working directory:
    ///
    /// The directory contains 3 files:
    /// + base.yaml: the base configuration file
    /// + local.yaml: the local configuration file
    /// + prod.yaml: the production configuration file
    ///
    /// base.yaml of the database directory contains the following:
    /// ```yaml
    /// postgres:
    ///  host: "localhost"
    ///  port: 5455
    ///  username: "postgres"
    ///  password: "password"
    ///  name: "kerberos"
    /// host:
    ///  protocol: "tcp" # or "udp"
    ///  as_port: 88
    ///  tgs_port: 89
    ///  host: "localhost"
    /// cache:
    ///  capacity: 1000
    ///  ttl: 3600 # in seconds
    /// ```
    /// local.yaml and prod.yaml may override the base.yaml and add additional fields:
    /// ```yaml
    /// postgres:
    ///  require_ssl: false
    /// ```
    fn load_from(
        dir: &str,
        as_config: AuthenticationServiceConfig,
        tgs_config: TicketGrantingServiceConfig,
    ) -> Result<Self, KdcSrvError> {
        let settings = PgDbSettings::load(dir);

        let server = load_server::<PgPool>(dir)
            .unwrap()
            .set_as_receiver(NpglAsReqHandler::new(as_config))
            .set_tgs_receiver(NpglTgsReqHandler::new(tgs_config))
            .use_postgres(settings, Krb5DbSchemaV1::boxed())
            .build(Protocol::Tcp)
            .unwrap();

        Ok(NpglKdcSrv::new(server))
    }
}

mod receivers;
mod types;
