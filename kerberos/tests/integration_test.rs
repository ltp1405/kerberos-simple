use kerberos::{
    client::Client,
    servers::{tcp_server::TcpServer, udp_server::UdpServer, Server},
};

#[tokio::test]
async fn test_tcp_client_request_and_respond() {
    let server = TcpServer::new("127.0.0.1:8080".parse().unwrap());
    tokio::spawn(async move {
        server.run().await.unwrap();
    });
    let client = Client::new_tcp("127.0.0.1:8081".parse().unwrap());
    let bytes = b"Hello, world!";
    let response = client
        .send_and_receive(bytes, "127.0.0.1:8080".parse().unwrap())
        .await;
    assert_eq!(response.unwrap(), b"Hello, world!".to_vec());
}

#[tokio::test]
async fn test_udp_client_request_and_respond() {
    let server = UdpServer::new("127.0.0.1:8080".parse().unwrap());
    tokio::spawn(async move {
        server.run().await.unwrap();
    });
    let client = Client::new_udp("127.0.0.1:8081".parse().unwrap());
    let bytes = b"Hello, world!";
    let response = client
        .send_and_receive(bytes, "127.0.0.1:8080".parse().unwrap())
        .await;
    assert_eq!(response.unwrap(), b"Hello, world!".to_vec());
}
