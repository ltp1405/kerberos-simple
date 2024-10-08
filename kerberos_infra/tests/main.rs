use der::Encode;
use kerberos_infra::{
    client::{Sendable, TcpClient},
    server::{
        database::{
            postgres::{schemas::Krb5DbSchemaV1, PgDbSettings},
            DbSettings,
        },
        load_server_from_dir,
        types::Protocol,
        Builder,
    },
};
use mocks::{Mapper, SimpleASReceiver, SimpleTgtReceiver};
use sqlx::PgPool;

#[tokio::test]
async fn tcp_client_should_be_able_to_communicate_with_tcp_server() {
    let (url, as_port, tgt_port) = ("127.0.0.1", 8080, 8081);

    // Step 1: Create a server
    let settings = PgDbSettings::load_from_dir();

    let schema = Krb5DbSchemaV1::boxed();

    let mut server = load_server_from_dir::<PgPool>()
        .unwrap()
        .set_as_receiver(SimpleASReceiver)
        .set_tgs_receiver(SimpleTgtReceiver)
        .use_postgres(settings, schema)
        .build(Protocol::Tcp)
        .expect("Failed to build server");

    // Step 2: Run the server in the background
    let handle = tokio::spawn(async move {
        server.prepare_and_run().await.unwrap();
    });

    // Wait for the server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 3: Create testcases and create a client for each testcase
    let mapper = Mapper::prepare();
    let testcases = vec![(as_port, mapper.random()), (tgt_port, mapper.random())];

    for (port, request) in testcases {
        let mut client = TcpClient::new(format!("{}:{}", url, port).parse().unwrap());

        // Step 4: Send the request to the server
        let encoded = der::asn1::OctetString::new(request)
            .unwrap()
            .to_der()
            .unwrap();
        let response = client.send(&encoded).await;

        // Step 5: Assert that the server received the request
        // and responded with the expected response
        assert!(response.is_ok(), "Failed to send request to server");
        assert_eq!(response.unwrap(), encoded);

        // Step 6: Close the stream on the client side
        let result = client.close().await;
        assert!(result.is_ok(), "Failed to close the client stream");
    }

    // Step 7: Shutdown the server
    handle.abort();
}

mod mocks;
