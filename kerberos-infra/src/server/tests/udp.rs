use tokio::net::UdpSocket;

use super::mocks::{MockASReceiver, MockTgtReceiver};

use crate::server::{Runnable, ServerBuilder, UdpServer};

#[tokio::test]
async fn server_builder_should_be_ok_when_given_all_entry_points() {
    let server = ServerBuilder::new("127.0.0.1")
        .as_entry(88, MockASReceiver)
        .tgt_entry(89, MockTgtReceiver)
        .build_udp();

    assert!(server.is_ok(), "UdpServer failed to build");

    let udp_server = server.unwrap();

    assert_eq!(
        udp_server.as_entry().0.port(),
        88,
        "AS port mismatch for UDP server"
    );
    assert_eq!(
        udp_server.tgt_entry().0.port(),
        89,
        "TGT port mismatch for UDP server"
    );
    assert_eq!(
        udp_server.as_entry().1,
        MockASReceiver,
        "AS receiver mismatch for UDP server"
    );
    assert_eq!(
        udp_server.tgt_entry().1,
        MockTgtReceiver,
        "TGT receiver mismatch for UDP server"
    );
}

#[tokio::test]
async fn server_builder_should_fail_when_missing_as_entry() {
    let server = ServerBuilder::<MockASReceiver, MockTgtReceiver>::new("127.0.0.1")
        .tgt_entry(89, MockTgtReceiver)
        .build_udp();

    assert!(
        server.is_err(),
        "UdpServer should fail when missing AS entry"
    );
}

#[tokio::test]
async fn server_should_be_able_to_handle_request() {
    let (mut server, shutdown_tx) = UdpServer::local(MockASReceiver, MockTgtReceiver);

    let (as_entry_addr, tgt_entry_addr) = (server.as_entry().0, server.tgt_entry().0);

    // Run the server in the background
    tokio::spawn({
        async move {
            server.run().await;
        }
    });

    // Give the server some time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let testcases = vec![
        (as_entry_addr, MockASReceiver::MOCK_MESSAGE),
        (tgt_entry_addr, MockTgtReceiver::MOCK_MESSAGE),
    ];

    for (addr, expected_response) in testcases {
        // Open a socket to the server
        let socket = UdpSocket::bind("127.0.0.1:4400").await.unwrap();
        socket.connect(addr).await.unwrap();

        // Simulate a request to the server
        let request = "Hello, world!";
        let attempt = socket.send(request.as_bytes()).await;
        assert!(attempt.is_ok(), "Failed to send request to AS server");

        // Get the response from the server
        let mut buffer = vec![0; 1024];
        let len = socket.recv(&mut buffer).await;
        assert!(len.is_ok(), "Failed to receive response from server");
        buffer.truncate(len.unwrap());

        let response = String::from_utf8(buffer).unwrap();

        assert_eq!(response, expected_response, "Response mismatch");
    }

    // Stop the server
    shutdown_tx.send(()).unwrap();
}
