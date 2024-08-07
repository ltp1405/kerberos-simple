use std::net::SocketAddr;

use kerberos::servers::Server;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let server = Server::new("127.0.0.1:8080".parse().expect("Unable to parse socket address"));
    server.run().await.expect("Unable to run server");
}