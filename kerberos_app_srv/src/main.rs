use std::sync::Arc;

use actix_web::{web::{self, Data}, App, HttpServer, Responder};
use database::AppDbSchema;
use kerberos::application_authentication_service::ApplicationAuthenticationServiceBuilder;
use kerberos_app_srv::{auth_cache, handleable::Handleable, handler::AppServerHandler};
use kerberos_infra::server::{database::postgres::PostgresDb, DbSettings, Migration, PgDbSettings};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = PgDbSettings::load_from_dir();
    let schema = AppDbSchema::boxed();
    let mut postgre = PostgresDb::new(config, schema);
    postgre.migrate_then_seed().await.unwrap();
    let db = Arc::new(postgre);
    let auth_service = ApplicationAuthenticationServiceBuilder::default().build();
    let auth_cache = auth_cache::ApplicationAuthenticationCache::new();
    let app_server_handler = AppServerHandler::new(db, auth_service, auth_cache);
    HttpServer::new(move || {
        App::new().app_data(web::Data::new(app_server_handler)).service(
            // prefixes all resources and routes attached to it...
            web::scope("/app")
                // ...so this handles requests for `GET /app/index.html`
                .route(
                    "/user/{username}",
                    web::get().to(AppServerHandler::get_user_profile),
                )
                .route(
                    "/authenticate",
                    web::post().to(AppServerHandler::authenticate),
                ),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

mod database;
