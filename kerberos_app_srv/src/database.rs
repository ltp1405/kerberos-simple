use kerberos_infra::server::database::{ClonableSchema, Schema};

extern crate kerberos;
extern crate kerberos_infra;

pub struct AppDbSchema;
impl AppDbSchema {
    pub fn boxed() -> Box<dyn ClonableSchema> {
        Box::new(AppDbSchema)
    }
}

impl Schema for AppDbSchema {
    fn schema_name(&self) -> String {
        format!("{}_{}", "srv", "v1")
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

                CREATE TABLE "{0}".UserProfile (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(255) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    firstname VARCHAR(255) NOT NULL,
                    lastname VARCHAR(255) NOT NULL,
                    birthday DATE NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
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

                -- Insert data into UserProfile table
                INSERT INTO "{0}".UserProfile (username, email, firstname, lastname, birthday)
                VALUES
                    ('admin', 'admin@gmail.com', 'Admin', 'Admin', '1990-01-01 00:00:00'),
                    ('toney', 'toney@hotmail.com', 'Toney', 'Jordan', '1990-12-01 00:00:00'),
                    ('user', 'user@gmail.com', 'User', 'User', '1990-01-02 00:00:00');
            COMMIT;
        "#,
            schema
        )
    }
}

impl ClonableSchema for AppDbSchema {
    fn clone_box(&self) -> Box<dyn ClonableSchema> {
        Box::new(AppDbSchema)
    }
}
