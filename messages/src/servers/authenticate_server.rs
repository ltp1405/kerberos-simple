use std::collections::HashMap;

use tokio::net::TcpStream;

use super::Database;

pub struct AS {
    database: Database,
}
impl AS {
    pub async fn respond_with_credentials(&self, mut client: TcpStream) -> tokio::io::Result<Vec<u8>> {
        todo!();
    }
    pub async fn receive_ticket(&self, mut client: TcpStream) -> tokio::io::Result<()> {
        todo!();
    }
}