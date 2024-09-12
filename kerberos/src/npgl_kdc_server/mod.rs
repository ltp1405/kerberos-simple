use kerberos_infra::server::Server;
use sqlx::PgPool;

pub struct NpglKdcSrv {
    inner: Server<PgPool>,
}

mod receivers;
