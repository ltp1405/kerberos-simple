use super::mocks::{MockASReceiver, MockTgtReceiver};

use crate::server::UdpServer;

#[tokio::test]
async fn server_builder_should_be_ok_when_given_all_entry_points() {
    let server = UdpServer::builder("127.0.0.1")
        .as_entry(88, MockASReceiver)
        .tgt_entry(89, MockTgtReceiver)
        .build();

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
