use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
};

use crate::server::infra::{KrbCache, KrbDatabase};
use crate::server::{
    infra::host::{
        builder::HostBuilder,
        tests::mocks::{MockCache, MockPool},
    },
    KrbAsyncReceiver,
};

use super::mocks::{MockASReceiver, MockTgsReceiver};

#[tokio::test]
async fn server_builder_should_be_ok_when_given_all_entry_points() {
    let server = HostBuilder::local()
        .set_as_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(MockASReceiver))))
        .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(
            MockTgsReceiver,
        ))))
        .boxed_tcp();

    assert!(server.is_ok(), "TcpServer failed to build");

    let tcp_server = server.unwrap();

    assert_eq!(
        tcp_server.get_as_addr().port(),
        88,
        "AS port mismatch for TCP server"
    );
    assert_eq!(
        tcp_server.get_tgs_addr().port(),
        89,
        "TGS port mismatch for TCP server"
    );
}

#[tokio::test]
async fn server_builder_should_fail_when_missing_as_entry() {
    let server = HostBuilder::local()
        .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(
            MockTgsReceiver,
        ))))
        .boxed_tcp();

    assert!(
        server.is_err(),
        "TcpServer should fail when missing AS entry"
    );
}

#[tokio::test]
async fn server_should_be_able_to_handle_request() {
    let mut server = HostBuilder::local()
        .set_as_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(MockASReceiver))))
        .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(
            MockTgsReceiver,
        ))))
        .boxed_tcp()
        .unwrap();

    let (as_entry_addr, tgt_entry_addr) = (server.get_as_addr(), server.get_tgs_addr());

    let cache: KrbCache = KrbCache::new(RwLock::new(Box::new(MockCache)));
    let pool: KrbDatabase = KrbDatabase::new(RwLock::new(Box::new(MockPool)));

    // Run the server in the background
    let handle = tokio::spawn({
        async move {
            server.run(pool, cache).await;
        }
    });

    // Give the server some time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let testcases = vec![
        (as_entry_addr, MockASReceiver::MOCK_MESSAGE),
        (tgt_entry_addr, MockTgsReceiver::MOCK_MESSAGE),
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
