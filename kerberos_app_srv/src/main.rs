use std::sync::Arc;

use actix_web::{web, App, HttpServer, Responder};
use database::AppDbSchema;
use kerberos_infra::server::database::{
    postgres::{PgDbSettings, PostgresDb},
    DbSettings, Migration,
};

async fn index(_data: web::Data<Arc<PostgresDb>>) -> impl Responder {
    "Hello world!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config = PgDbSettings::load_from_dir();
    let schema = AppDbSchema::boxed();

    let mut postgre = PostgresDb::new(config, schema);
    postgre.migrate_then_seed().await.unwrap();
    let db = Arc::new(postgre);
    HttpServer::new(move || {
        App::new().app_data(web::Data::new(db.clone())).service(
            // prefixes all resources and routes attached to it...
            web::scope("/app")
                // ...so this handles requests for `GET /app/index.html`
                .route("/index.html", web::get().to(index))
                .route("/index.html", web::post().to(index)),
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}

mod database;
