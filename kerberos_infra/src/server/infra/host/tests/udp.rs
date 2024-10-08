use tokio::sync::RwLock;

use tokio::net::UdpSocket;

use super::mocks::{MockASReceiver, MockTgsReceiver};

use crate::server::infra::{
    host::{
        tests::mocks::{MockCache, MockPool},
        HostBuilder,
    },
    KrbAsyncReceiver, KrbCache, KrbDatabase,
};

#[tokio::test]
async fn server_builder_should_be_ok_when_given_all_entry_points() {
    let server = HostBuilder::local()
        .set_as_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(MockASReceiver))))
        .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(
            MockTgsReceiver,
        ))))
        .boxed_udp();

    assert!(server.is_ok(), "UdpServer failed to build");

    let udp_server = server.unwrap();

    assert_eq!(
        udp_server.get_as_addr().port(),
        88,
        "AS port mismatch for UDP server"
    );
    assert_eq!(
        udp_server.get_tgs_addr().port(),
        89,
        "TGT port mismatch for UDP server"
    );
}

#[tokio::test]
async fn server_builder_should_fail_when_missing_as_entry() {
    let server = HostBuilder::local()
        .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(
            MockTgsReceiver,
        ))))
        .boxed_udp();

    assert!(
        server.is_err(),
        "UdpServer should fail when missing AS entry"
    );
}

#[tokio::test]
async fn server_should_be_able_to_handle_request() {
    let mut server = HostBuilder::local()
        .set_as_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(MockASReceiver))))
        .set_tgs_receiver(KrbAsyncReceiver::new(RwLock::new(Box::new(
            MockTgsReceiver,
        ))))
        .boxed_udp()
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
    handle.abort();
}
