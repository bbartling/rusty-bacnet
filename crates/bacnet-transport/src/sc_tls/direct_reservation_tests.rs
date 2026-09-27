//! Deterministic write failure/cancellation seam with a real TLS incumbent.
use super::super::super::{serve_handshake, DirectWs, DirectWsRead};
use super::*;
use tokio::sync::oneshot;

struct Read(Option<Vec<u8>>);
impl DirectWsRead for Read {
    async fn next_data(&mut self) -> Option<Result<Vec<u8>, String>> {
        self.0.take().map(Ok)
    }
}
struct Write {
    entered: Option<oneshot::Sender<()>>,
    fail: bool,
}
impl DirectWs for Write {
    type Read = Read;
    async fn send_data(&mut self, bytes: &[u8]) -> Result<(), ()> {
        assert_eq!(
            decode_sc_message(bytes).unwrap().function,
            ScFunction::ConnectAccept
        );
        self.entered.take().unwrap().send(()).unwrap();
        if self.fail {
            Err(())
        } else {
            std::future::pending().await
        }
    }
    async fn send_close(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

#[tokio::test]
async fn failed_cancelled_timed_out_accept_preserves_real_tls_incumbent() {
    let ca = TestCa::generate();
    let (mut listener, mut rx) = start_listener(&ca, |c| c.with_max_established_peers(1)).await;
    let (old, _) = connect_claim(&listener, &ca, DIAL_VMAC, DIAL_UUID).await;
    let config = DirectAcceptConfig::new(
        loopback_addr(),
        LISTENER_VMAC,
        LISTENER_UUID,
        ca.node_config(vec!["localhost".into()]),
    )
    .with_max_established_peers(1);
    for mode in 0..3 {
        let mut conn = ScConnection::new([0x23; 6], DIAL_UUID);
        let mut buf = BytesMut::new();
        encode_sc_message(&mut buf, &conn.build_connect_request());
        let mut read = Read(Some(buf.to_vec()));
        let (entered, barrier) = oneshot::channel();
        let mut write = Write {
            entered: Some(entered),
            fail: mode == 0,
        };
        {
            let future = serve_handshake(
                &mut write,
                &mut read,
                &config,
                loopback_addr(),
                &listener.membership,
            );
            tokio::pin!(future);
            if mode == 0 {
                assert!(future.await.is_none());
            } else {
                tokio::select! { _ = barrier => {}, _ = &mut future => panic!("send must wait") }
                assert_eq!(listener.membership.counts(), (1, 1));
                if mode == 2 {
                    assert!(tokio::time::timeout(Duration::from_millis(1), &mut future)
                        .await
                        .is_err());
                }
                // Dropping the pinned future is explicit caller cancellation.
            }
        }
        assert_eq!(listener.membership.counts(), (1, 0));
        assert_routable(&old, &mut rx, DIAL_VMAC).await;
    }
    listener.stop().await;
}

#[test]
fn generation_survives_owner_restarts_and_late_cleanup_cannot_erase_successor() {
    use crate::sc::direct_membership::{DirectMembership, DirectRole};
    use std::sync::Arc;
    let registry = Arc::new(DirectMembership::default());
    let a = registry
        .reserve(
            DIAL_UUID,
            DIAL_VMAC,
            LISTENER_UUID,
            LISTENER_VMAC,
            DirectRole::Accepted,
            1,
        )
        .unwrap()
        .commit();
    let b = registry
        .reserve(
            DIAL_UUID,
            [0x23; 6],
            LISTENER_UUID,
            LISTENER_VMAC,
            DirectRole::Accepted,
            1,
        )
        .unwrap()
        .commit();
    assert_ne!(a.generation, b.generation);
    assert!(a.with_current(|| panic!("stale NPDU callback")).is_none());
    a.retire();
    drop(a);
    assert!(b.is_current());
    let last = b.generation;
    drop(b);
    drop(registry);
    let restarted = Arc::new(DirectMembership::default());
    let c = restarted
        .reserve(
            DIAL_UUID,
            DIAL_VMAC,
            LISTENER_UUID,
            LISTENER_VMAC,
            DirectRole::Accepted,
            1,
        )
        .unwrap()
        .commit();
    assert!(c.generation > last);
}
