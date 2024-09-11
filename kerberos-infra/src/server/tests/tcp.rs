use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::mocks::{MockASReceiver, MockTgtReceiver};

use crate::server::{tcp::TcpServer, Runnable, ServerBuilder};

#[tokio::test]
async fn server_builder_should_be_ok_when_given_all_entry_points() {
    let server = ServerBuilder::new("127.0.0.1")
        .as_entry(88, MockASReceiver)
        .tgt_entry(89, MockTgtReceiver)
        .build_tcp();

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
    let server = ServerBuilder::<MockASReceiver, MockTgtReceiver>::new("127.0.0.1")
        .tgt_entry(89, MockTgtReceiver)
        .build_tcp();

    assert!(
        server.is_err(),
        "TcpServer should fail when missing AS entry"
    );
}

#[tokio::test]
async fn server_should_be_able_to_handle_request() {
    let mut server = TcpServer::local(MockASReceiver, MockTgtReceiver);

    let (as_entry_addr, tgt_entry_addr) = (server.as_entry().0, server.tgt_entry().0);

    // Run the server in the background
    let handle = tokio::spawn({
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
        // Open a stream to the server
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Simulate a request to the server
        let request = "Hello, world!";
        let request_bytes = request.as_bytes();
        let length_prefix = request_bytes.len().to_be_bytes();

        let attempt = stream.write_all(&length_prefix).await;
        assert!(attempt.is_ok(), "Failed to send length prefix to server");

        // Make sure the server does not respond before the request is fully sent
        let attempt = stream.try_read(&mut [0; 1]);
        assert!(
            attempt.is_err(),
            "Server responded before request was fully sent"
        );

        let attempt = stream.write_all(request_bytes).await;
        assert!(attempt.is_ok(), "Failed to send request to AS server");

        // Get the response from the server
        let mut buffer = vec![0; 1024];
        let len = stream.read(&mut buffer).await.unwrap();
        buffer.truncate(len);

        let expected_length = expected_response.as_bytes().len() + 4;
        assert_eq!(buffer.len(), expected_length, "Response length mismatch");

        let response = String::from_utf8(buffer).unwrap();

        assert_eq!(response, expected_response, "Response mismatch");
    }

    // Stop the server
    handle.abort();
}

#[tokio::test]
async fn server_rejects_request_if_highest_bit_is_set() {
    let mut server = TcpServer::local(MockASReceiver, MockTgtReceiver);

    let (as_entry_addr, tgt_entry_addr) = (server.as_entry().0, server.tgt_entry().0);

    // Run the server in the background
    let handle = tokio::spawn({
        async move {
            server.run().await;
        }
    });

    // Give the server some time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let testcases = vec![
        (
            as_entry_addr,
            MockASReceiver::MOCK_INVALID_LENGTH_PREFIX,
            MockASReceiver::MOCK_INVALID_LENGTH_PREFIX_RESPONSE,
        ),
        (
            tgt_entry_addr,
            MockTgtReceiver::MOCK_INVALID_LENGTH_PREFIX,
            MockTgtReceiver::MOCK_INVALID_LENGTH_PREFIX_RESPONSE,
        ),
    ];

    for (addr, length_prefix, expected_response) in testcases {
        // Open a stream to the server
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Simulate a request to the server
        let length_prefix = length_prefix.to_be_bytes();
        let attempt = stream.write_all(&length_prefix).await;
        assert!(attempt.is_ok(), "Failed to send length prefix to server");

        // Make sure the server rejects the request
        let mut buffer = vec![0; 1024];
        let attempt = stream.read(&mut buffer).await;
        assert!(attempt.is_ok(), "Failed to read response from server");
        buffer.truncate(attempt.unwrap());

        let expected_length = expected_response.as_bytes().len() + 4;
        assert_eq!(buffer.len(), expected_length, "Response length mismatch");

        let message = String::from_utf8(buffer).unwrap();
        assert_eq!(message, expected_response, "Response mismatch");
    }

    // Stop the server
    handle.abort();
}
