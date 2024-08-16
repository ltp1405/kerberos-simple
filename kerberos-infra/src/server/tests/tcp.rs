use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use super::mocks::{MockASReceiver, MockTgtReceiver};

use crate::server::{Runnable, TcpServer};

#[tokio::test]
async fn server_builder_should_be_ok_when_given_all_entry_points() {
    let server = TcpServer::builder("127.0.0.1")
        .as_entry(88, MockASReceiver)
        .tgt_entry(89, MockTgtReceiver)
        .build();

    assert!(server.is_ok(), "TcpServer failed to build");

    let tcp_server = server.unwrap();

    assert_eq!(
        tcp_server.as_entry().0.port(),
        88,
        "AS port mismatch for TCP server"
    );
    assert_eq!(
        tcp_server.tgt_entry().0.port(),
        89,
        "TGT port mismatch for TCP server"
    );
    assert_eq!(
        tcp_server.as_entry().1,
        MockASReceiver,
        "AS receiver mismatch for TCP server"
    );
    assert_eq!(
        tcp_server.tgt_entry().1,
        MockTgtReceiver,
        "TGT receiver mismatch for TCP server"
    );
}

#[tokio::test]
async fn server_builder_should_fail_when_missing_as_entry() {
    let server = TcpServer::<MockASReceiver, MockTgtReceiver>::builder("127.0.0.1")
        .tgt_entry(89, MockTgtReceiver)
        .build();

    assert!(
        server.is_err(),
        "TcpServer should fail when missing AS entry"
    );
}

#[tokio::test]
async fn server_should_be_able_to_handle_request() {
    let server = Arc::new(Mutex::new(TcpServer::local(
        MockASReceiver,
        MockTgtReceiver,
    )));

    // Run the server in the background
    tokio::spawn({
        let server = server.clone();
        async move {
            server.lock().await.run().await.unwrap();
            println!("Server is running");
        }
    });

    // Give the server some time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Open a stream to the server
    let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

    // Simulate a request to the server
    let request = "Hello, world!";
    let response = stream.write_all(request.as_bytes()).await;

    assert!(response.is_ok(), "Failed to send request to AS server");

    // Get the response from the server
    let mut buffer = vec![0; 1024];
    let len = stream.read(&mut buffer).await.unwrap();
    buffer.truncate(len);

    let response = String::from_utf8(buffer).unwrap();

    assert_eq!(response, MockASReceiver::MOCK_MESSAGE, "Response mismatch");

    // Stop the server
    server.lock().await.stop().unwrap();
}
