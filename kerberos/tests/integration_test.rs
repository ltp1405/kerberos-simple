use kerberos::{
    client::{tcp_client::TcpClient, udp_client::UdpClient, Client},
    servers::{tcp_server::TcpServer, udp_server::UdpServer, Server},
};

#[tokio::test]
async fn test_tcp_client_send_and_receive_and_server_run() {
    let server = TcpServer::new("127.0.0.1:8080".parse().unwrap());
    tokio::spawn(async move {
        server.run().await.unwrap();
    });
    let mut client = TcpClient::new("127.0.0.1:8081".parse().unwrap());
    let bytes = b"Hello, world!";
    let response = client
        .send_and_receive(bytes, "127.0.0.1:8080".parse().unwrap())
        .await;
    assert_eq!(response.unwrap(), b"Hello, world!".to_vec());
}

#[tokio::test]
async fn test_udp_client_send_and_receive_and_server_run() {
    let server = UdpServer::new("127.0.0.1:8080".parse().unwrap());
    tokio::spawn(async move {
        server.run().await.unwrap();
    });
    let mut client = UdpClient::new("127.0.0.1:8081".parse().unwrap()).await;
    let bytes = b"Hello, world!";
    let response = client
        .send_and_receive(bytes, "127.0.0.1:8080".parse().unwrap())
        .await;
    assert_eq!(response.unwrap(), b"Hello, world!".to_vec());
}
