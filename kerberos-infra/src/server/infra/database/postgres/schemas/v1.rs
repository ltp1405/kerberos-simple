use crate::server::infra::database::Schema;

pub struct Krb5DbSchemaV1;

impl Krb5DbSchemaV1 {
    #[allow(dead_code)]
    pub fn boxed() -> Box<dyn Schema> {
        Box::new(Krb5DbSchemaV1)
    }
}

impl Schema for Krb5DbSchemaV1 {
    fn schema_name(&self) -> String {
        format!("{}_{}", "krb5", "v1")
    }

    fn get_schema(&self) -> String {
        let schema = self.schema_name();
        format!(
            r#"
            BEGIN;

                -- Drop the schema if it exists
                DROP SCHEMA IF EXISTS "{0}" CASCADE;

                -- Create the schema
                CREATE SCHEMA "{0}";

                -- Create TicketPolicy table
                CREATE TABLE "{0}".TicketPolicy (
                    realm VARCHAR(255) PRIMARY KEY,
                    maximum_ticket_lifetime BIGINT NOT NULL CHECK (maximum_ticket_lifetime >= 0),
                    maximum_renewable_lifetime BIGINT NOT NULL CHECK (maximum_renewable_lifetime >= 0),
                    minimum_ticket_lifetime BIGINT NOT NULL CHECK (minimum_ticket_lifetime >= 0),
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                -- Create Principal table
                CREATE TABLE "{0}".Principal (
                    principal_name VARCHAR(255) PRIMARY KEY,
                    realm VARCHAR(255) REFERENCES "{0}".TicketPolicy(realm),
                    flags INT NOT NULL CHECK (flags >= 0 AND flags <= 0xFFFFFFFF),
                    expire TIMESTAMP NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                -- Create Encrypt table
                CREATE TABLE "{0}".Encrypt (
                    etype INT PRIMARY KEY,
                    method VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                -- Create Checksum table
                CREATE TABLE "{0}".Checksum (
                    ctype INT PRIMARY KEY,
                    method VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                -- Create Key table
                CREATE TABLE "{0}".Key (
                    principal_name VARCHAR(255),
                    etype INT,
                    secret_key VARCHAR(1024) NOT NULL,
                    knvno INT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (principal_name, etype),
                    FOREIGN KEY (principal_name) REFERENCES "{0}".Principal(principal_name),
                    FOREIGN KEY (etype) REFERENCES "{0}".Encrypt(etype)
                );

            COMMIT;
        "#,
            schema
        )
    }

    fn seed_data(&self) -> String {
        let schema = self.schema_name();
        format!(
            r#"
            BEGIN;

                    INSERT INTO "{0}".TicketPolicy (realm, maximum_ticket_lifetime, maximum_renewable_lifetime, minimum_ticket_lifetime, created_at, updated_at)
                    VALUES ('MYREALM.COM', 7200, 6000, 5400, '2021-01-01 00:00:00', '2021-01-01 00:00:00'),
                           ('EXAMPLE.COM', 7200, 6000, 5400, '2021-01-01 00:00:00', '2021-01-01 00:00:00'),
                           ('EXAMPLE.ORG', 7200, 6000, 5400, '2021-01-01 00:00:00', '2021-01-01 00:00:00');

                    INSERT INTO "{0}".Principal (principal_name, realm, flags, expire)
                    VALUES ('toney', 'MYREALM.COM', 0, '2025-12-31 23:59:59'),
                           ('steve', 'EXAMPLE.COM', 0, '2025-12-31 23:59:59'),
                           ('janice', 'MYREALM.COM', 0, '2025-12-31 23:59:59'),
                           ('david', 'EXAMPLE.ORG', 0, '2025-12-31 23:59:59');

                    -- Expired principals
                    INSERT INTO "{0}".Principal (principal_name, realm, flags, expire, created_at, updated_at)
                    VALUES ('donald', 'EXAMPLE.COM', 0, '2023-12-31 23:59:59', '2021-02-01 00:00:00', '2021-02-01 00:00:00'),
                           ('benjamin', 'EXAMPLE.ORG', 0, '2023-12-31 23:59:59', '2021-02-01 00:00:00', '2021-02-01 00:00:00');

                    INSERT INTO "{0}".Encrypt (etype, method, created_at, updated_at)
                    VALUES (17, 'aes128-cts-hmac-sha1-96', '2021-01-01 00:00:00', '2021-01-01 00:00:00'),
                           (18, 'aes256-cts-hmac-sha1-96', '2021-01-01 00:00:00', '2021-01-01 00:00:00'),
                           (19, 'aes128-cts-hmac-sha256-128', '2021-01-01 00:00:00', '2021-01-01 00:00:00');

                    INSERT INTO "{0}".Checksum (ctype, method, created_at, updated_at)
                    VALUES (16, 'hmac-sha1-96-aes256', '2021-01-01 00:00:00', '2021-01-01 00:00:00');

                    INSERT INTO "{0}".Key (principal_name, etype, secret_key, knvno, created_at, updated_at)
                    VALUES ('toney', 17, 'uJV4sOr09XwCdIIjKjB7CV3zZdBmWVRt', 1, '2023-01-01 00:00:00', '2023-01-01 00:00:00'),
                           ('steve', 17, 'VwTyeYkpChVj63Qg3KK4VbGyvi9ZwOaA', 1, '2023-01-01 00:00:00', '2023-01-01 00:00:00'),
                           ('janice', 17, 'kBgzBnJ9gO81twZT39Kxu3or8ngHyVM7', 1, '2023-01-01 00:00:00', '2023-01-01 00:00:00'),
                           ('david', 17, '22IzIa3qlwgRU1R7YOiRv9yamdN05sOK', 2, '2022-08-25 00:00:00', '2022-08-25 00:00:00'),
                           ('donald', 18, 'G0kL9hKLD7B4WogLFPInyglRtnCbTrJA', 3, '2022-08-25 00:00:00', '2022-08-25 00:00:00'),
                           ('benjamin', 19, 'u8YNSG06O8ENHJH9Hhunc81gBXHSgn0g', 5, '2022-08-25 00:00:00', '2022-08-25 00:00:00');

            COMMIT;
        "#,
            schema
        )
    }
}
