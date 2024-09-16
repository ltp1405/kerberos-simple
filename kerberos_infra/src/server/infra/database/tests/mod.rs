use secrecy::ExposeSecret;
use uuid::Uuid;

use crate::server::{
    database::{postgres::PgDbSettings, DbSettings, KrbV5Queryable},
    infra::database::{postgres::PostgresDb, Krb5DbSchemaV1},
};

#[tokio::test]
async fn user_should_be_able_to_connect_to_db_through_config() {
    let config = PgDbSettings::load("src/server/infra/database/server/config/database");

    let schema = Krb5DbSchemaV1::boxed();

    _ = PostgresDb::boxed(config, schema);
}

#[tokio::test]
async fn postgres_db_should_migrate_schema_and_seed_data_when_called() {
    let config = {
        let mut initial = PgDbSettings::load("src/server/infra/database/server/config/database");
        initial.name = Uuid::new_v4().to_string().into();
        initial
    };

    let schema = Krb5DbSchemaV1::boxed();

    let mut db = PostgresDb::boxed(config, schema);

    let result = db.migrate_then_seed().await;

    assert!(
        result.is_ok(),
        "Failed to migrate and seed database {:?}",
        result
    );
}

#[tokio::test]
async fn query_principal_should_return_principal_when_principal_exists() {
    let config = {
        let mut initial = PgDbSettings::load("src/server/infra/database/server/config/database");
        initial.name = Uuid::new_v4().to_string().into();
        initial
    };

    let schema = Krb5DbSchemaV1::boxed();

    let mut db = PostgresDb::boxed(config, schema);

    let result = db.migrate_then_seed().await;

    assert!(
        result.is_ok(),
        "Failed to migrate and seed database {:?}",
        result
    );

    let principal = db.get_principal("toney", "MYREALM.COM").await;

    assert!(principal.is_ok(), "Failed to get principal {:?}", principal);

    let principal = principal.unwrap();

    assert!(principal.is_some(), "Principal not found {:?}", principal);

    let principal = principal.unwrap();

    assert_eq!(principal.principal_name, "toney");

    assert_eq!(principal.realm, "MYREALM.COM");

    assert_eq!(principal.supported_enctypes, vec![17]);

    assert_eq!(principal.p_kvno, 1);

    assert_eq!(
        principal.key.expose_secret(),
        "uJV4sOr09XwCdIIjKjB7CV3zZdBmWVRt"
    );

    assert_eq!(principal.max_lifetime, 7200);

    assert_eq!(principal.max_renewable_life, 6000);
}
