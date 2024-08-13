use std::net::SocketAddr;

use crate::servers::Server;
use crate::transporters::Transporter;

pub struct Client {
    addr: SocketAddr,
}

impl Client {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
    pub fn addr(&self) -> SocketAddr {
        return self.addr;
    }
    pub async fn request_and_respond<T: Transporter>(
        &self,
        request: &[u8],
        destination: Server<T>,
    ) -> tokio::io::Result<Vec<u8>> {
        let mut transporter = T::new(self.addr).await;
        transporter
            .connect(destination.addr())
            .await
            .expect("Unable to connect to server");
        transporter
            .write(request)
            .await
            .expect("Unable to write to server");
        let mut buffer = vec![0; 1];
        transporter
            .read(&mut buffer)
            .await
            .expect("Unable to read from server");
        Ok(buffer)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        client::Client,
        servers::Server,
        transporters::{tcp_transporter::TcpTransporter, udp_transporter::UdpTransporter},
    };

    #[tokio::test]
    async fn test_tcp_client_request_and_respond() {
        let mock_server = mockito::Server::new_async().await;
        println!("new mock server has been created!");
        let server_addr = mock_server.host_with_port();
        println!("new server has been created!");
        let server_addr_cloned = server_addr.clone();
        
        // tokio::spawn(async move {
            println!("server is running!");
            let mut server: Server<TcpTransporter> = Server::<TcpTransporter>::new(
                server_addr_cloned.parse().expect("unable to parse socket address"),
            ).await;
            server.run().await.expect("unable to run server");
        // }).await.expect("unable to run server");
        // let client = Client::new(
        //     "127.0.0.1:8080"
        //         .parse()
        //         .expect("unable to parse socket address"),
        // );
        // let server = Server::<TcpTransporter>::new(
        //     server_addr.clone().parse().expect("unable to parse socket address"),
        // ).await;
        // let response = client
        //     .request_and_respond(b"hello", server)
        //     .await
        //     .expect("unable to request and respond");
        // assert_eq!(response, b"hello".to_vec());
    }

    #[tokio::test]
    async fn test_udp_client_request_and_respond() {
        let mock_server = mockito::Server::new_async().await;
        let server_addr = mock_server.host_with_port();
        let server = Server::<UdpTransporter>::new(
            server_addr.parse().expect("unable to parse socket address"),
        )
        .await;
        let client = Client::new(
            "127.0.0.1:8080"
                .parse()
                .expect("unable to parse socket address"),
        );
        let response = client
            .request_and_respond(b"hello", server)
            .await
            .expect("unable to request and respond");
        assert_eq!(response, b"hello".to_vec());
    }
}
