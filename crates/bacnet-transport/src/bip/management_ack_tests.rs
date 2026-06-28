use super::*;
use tokio::time::{timeout, Duration};

async fn malformed_management_ack(function: BvlcFunction, payload_len: usize) -> Error {
    let server = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let server_port = server.local_addr().unwrap().port();
    let server_mac = encode_bip_mac(Ipv4Addr::LOCALHOST.octets(), server_port);

    let responder = tokio::spawn(async move {
        let mut recv_buf = [0u8; 2048];
        let (_len, client_addr) = timeout(Duration::from_secs(2), server.recv_from(&mut recv_buf))
            .await
            .expect("timed out waiting for management request")
            .unwrap();

        let payload = vec![0; payload_len];
        let mut response = BytesMut::with_capacity(4 + payload.len());
        encode_bvll(&mut response, function, &payload).unwrap();
        server.send_to(&response, client_addr).await.unwrap();
    });

    let mut client = BipTransport::new(Ipv4Addr::LOCALHOST, 0, Ipv4Addr::BROADCAST);
    let _client_rx = client.start().await.unwrap();

    let err = match function {
        BvlcFunction::READ_BROADCAST_DISTRIBUTION_TABLE_ACK => {
            client.read_bdt(&server_mac).await.unwrap_err()
        }
        BvlcFunction::READ_FOREIGN_DEVICE_TABLE_ACK => {
            client.read_fdt(&server_mac).await.unwrap_err()
        }
        _ => unreachable!("test helper only supports BDT/FDT management ACKs"),
    };

    client.stop().await.unwrap();
    responder.await.unwrap();

    err
}

#[tokio::test]
async fn read_bdt_rejects_malformed_ack_payload_length() {
    let err = malformed_management_ack(
        BvlcFunction::READ_BROADCAST_DISTRIBUTION_TABLE_ACK,
        bbmd::BDT_ENTRY_SIZE - 1,
    )
    .await;

    assert!(
        format!("{err}").contains("BDT data length 9 not a multiple of 10"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn read_fdt_rejects_malformed_ack_payload_length() {
    let err = malformed_management_ack(
        BvlcFunction::READ_FOREIGN_DEVICE_TABLE_ACK,
        bbmd::FDT_ENTRY_SIZE - 1,
    )
    .await;

    assert!(
        format!("{err}").contains("FDT data length 9 not a multiple of 10"),
        "unexpected error: {err}"
    );
}
