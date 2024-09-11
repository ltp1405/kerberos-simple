use std::time::Duration;

use async_trait::async_trait;
use secrecy::{ExposeSecret, Secret};
pub use settings::PgDbSettings;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool, Row};

use super::{
    view::PrincipalComplexView, Database, DatabaseError, DatabaseResult, Migration, Queryable,
    Schema,
};

pub use schemas::Krb5DbSchemaV1;

pub struct PostgresDb {
    pool: PgPool,
    settings: PgDbSettings,
    schema: Box<dyn Schema>,
}

impl PostgresDb {
    pub fn boxed(settings: PgDbSettings, schema: Box<dyn Schema>) -> Box<dyn Database> {
        Box::new(PostgresDb {
            pool: Self::without_db(&settings),
            settings,
            schema,
        })
    }

    fn without_db(settings: &PgDbSettings) -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy_with(settings.without_db())
    }

    fn with_db(settings: &PgDbSettings) -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(2))
            .connect_lazy_with(settings.with_db())
    }
}

unsafe impl Send for PostgresDb {}

unsafe impl Sync for PostgresDb {}

#[async_trait]
impl Migration for PostgresDb {
    async fn migrate_then_seed(&mut self) -> DatabaseResult {
        // Create the database if it does not exist
        let missing_db = self
            .pool
            .fetch_optional(
                format!(
                    r#"SELECT 1 FROM pg_database WHERE datname = '{}';"#,
                    self.settings.name.expose_secret()
                )
                .as_str(),
            )
            .await
            .map(|row| row.is_none())?;

        if missing_db {
            self.pool
                .execute(
                    format!(
                        r#"CREATE DATABASE "{}";"#,
                        self.settings.name.expose_secret()
                    )
                    .as_str(),
                )
                .await?;
        }

        // Connect to the database
        self.pool = Self::with_db(&self.settings);

        // Initialize the database schema
        self.pool.execute(self.schema.get_schema().as_ref()).await?;

        // Seeding the database
        self.pool.execute(self.schema.seed_data().as_ref()).await?;

        Ok(())
    }
}

#[async_trait]
impl Queryable for PostgresDb {
    async fn get_principal(
        &self,
        principal_name: &str,
        realm: &str,
    ) -> DatabaseResult<Option<PrincipalComplexView>> {
        let schema = self.schema.schema_name();

        let result = self.pool.fetch_optional(
            format!(r#"
                SELECT
                    p.principal_name,
                    p.realm,
                    k.secret_key as key,
                    k.knvno,
                    k.etype,
                    tp.maximum_ticket_lifetime as maximum_lifetime,
                    tp.maximum_renewable_lifetime as maximum_renewable_life
                FROM
                    (
                        SELECT principal_name, realm, expire
                        FROM "{0}".Principal
                        WHERE principal_name = '{1}' AND realm = '{2}'
                    ) AS p
                    JOIN
                        "{0}".Key k ON p.principal_name = k.principal_name
                    JOIN
                        (
                            SELECT realm, maximum_ticket_lifetime, maximum_renewable_lifetime, minimum_ticket_lifetime
                            FROM "{0}".TicketPolicy
                        )
                        AS tp ON p.realm = tp.realm;
            "#, schema, principal_name, realm).as_str()
        ).await.map_err(|e| {
            println!("{:?}", e);
            e
        })?.map(|row| PrincipalComplexView {
            principal_name: row.get(0),
            realm: row.get(1),
            key: Secret::new(row.get(2)),
            p_kvno: row.get(3),
            supported_enctypes: vec![row.get(4)],
            max_lifetime: row.get(5),
            max_renewable_life: row.get(6),
        });

        Ok(result)
    }
}

#[async_trait]
impl Database for PostgresDb {}

impl From<sqlx::Error> for DatabaseError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::Configuration(_) => DatabaseError::ConfigurationError,
            sqlx::Error::Database(_) => DatabaseError::OperationalError,
            sqlx::Error::Io(_) => DatabaseError::ConnectionError,
            sqlx::Error::Tls(_) => DatabaseError::ConnectionError,
            sqlx::Error::Protocol(_) => DatabaseError::OperationalError,
            sqlx::Error::Encode(_) => DatabaseError::InvalidRequest,
            sqlx::Error::Decode(_) => DatabaseError::InvalidRequest,
            sqlx::Error::AnyDriverError(_) => DatabaseError::OperationalError,
            sqlx::Error::PoolTimedOut => DatabaseError::ConnectionError,
            sqlx::Error::PoolClosed => DatabaseError::ConnectionError,
            sqlx::Error::WorkerCrashed => DatabaseError::InternalError,
            sqlx::Error::Migrate(_) => DatabaseError::OperationalError,
            _ => DatabaseError::InternalError,
        }
    }
}

mod schemas;

mod settings;
