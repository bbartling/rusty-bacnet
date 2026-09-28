//! Deterministic scheduling and blocked-writer controls on the production loop.
use super::*;
use crate::port::{DirectResponse, DirectResponseScope, DirectScIdentity};
use std::sync::atomic::AtomicUsize;
use tokio::sync::oneshot;

struct Read(bool);
impl DirectWsRead for Read {
    async fn next_data(&mut self) -> Option<Result<Vec<u8>, String>> {
        if self.0 {
            Some(Ok(vec![0xff]))
        } else {
            std::future::pending().await
        }
    }
}
struct Write {
    writes: Arc<AtomicUsize>,
    entered: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}
impl DirectWs for Write {
    type Read = Read;
    async fn send_data(&mut self, data: &[u8]) -> Result<(), ()> {
        if decode_sc_message(data).unwrap().function == ScFunction::EncapsulatedNpdu {
            self.writes.fetch_add(1, Ordering::AcqRel);
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            if let Some(release) = self.release.take() {
                release.await.map_err(|_| ())?;
            }
        }
        Ok(())
    }
    async fn send_close(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
fn route() -> (
    Arc<Membership>,
    DirectResponse,
    mpsc::Receiver<crate::direct_response::ResponseWrite>,
) {
    let registry = Arc::new(DirectMembership::default());
    let member = registry
        .reserve([1; 16], [1; 6], [2; 16], [2; 6], DirectRole::Accepted, 1)
        .unwrap()
        .commit();
    let identity = DirectScIdentity::verified([3; 32], member.generation);
    let (route, recv) = DirectResponse::new(&member, identity, (100, 96), Duration::from_secs(10));
    (member, route, recv)
}
#[tokio::test]
async fn direct_response_ready_read_and_queue_have_bounded_alternating_progress() {
    let (_member, route, mut recv) = route();
    let scope = DirectResponseScope::default();
    let mut send = Box::pin(route.send(&[1, 0], &scope));
    assert!(futures_util::poll!(&mut send).is_pending());
    let mut read = Read(true);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    assert!(matches!(
        next_event::<Write>(&mut read, &mut recv, false, deadline).await,
        Event::Read(_)
    ));
    let Event::Write(Some(write)) = next_event::<Write>(&mut read, &mut recv, true, deadline).await
    else {
        panic!("ready read starved queued send")
    };
    write.done.send(Ok(())).unwrap();
    send.await.unwrap();
    let mut send = Box::pin(route.send(&[1, 0], &scope));
    assert!(futures_util::poll!(&mut send).is_pending());
    assert!(
        matches!(
            next_event::<Write>(&mut read, &mut recv, false, deadline).await,
            Event::Read(_)
        ),
        "ready queue must not starve control"
    );
}

async fn worker(
    member: Arc<Membership>,
    route: DirectResponse,
    mut recv: mpsc::Receiver<crate::direct_response::ResponseWrite>,
    mut write: Write,
) {
    let ca = super::super::direct_accept_tests::TestCa::generate();
    let config = DirectAcceptConfig::new(
        "127.0.0.1:0".parse().unwrap(),
        [2; 6],
        [2; 16],
        ca.node_config(vec!["localhost".into()]),
    )
    .with_connect_timeout(Duration::from_secs(5));
    let _retire = RetireMember(&member);
    let (tx, _rx) = mpsc::channel(4);
    let admission = Arc::new(ScNpduAdmission::new(ScNpduAdmissionPolicy::default()));
    serve_npdu_loop(
        &mut write,
        &mut Read(false),
        &config,
        AdmittedDirectPeer {
            address: "127.0.0.1:1".parse().unwrap(),
            member: &member,
            identity: route.identity(),
            response: route,
        },
        &tx,
        &admission,
        &mut recv,
    )
    .await;
}

#[tokio::test]
async fn direct_response_started_write_may_finish_but_sealed_queued_write_cannot_start() {
    let (member, route, recv) = route();
    let scope = DirectResponseScope::default();
    let (entered, barrier) = oneshot::channel();
    let (release, gate) = oneshot::channel();
    let writes = Arc::new(AtomicUsize::new(0));
    let worker = tokio::spawn(worker(
        member.clone(),
        route.clone(),
        recv,
        Write {
            writes: writes.clone(),
            entered: Some(entered),
            release: Some(gate),
        },
    ));
    let mut first = Box::pin(route.send(&[1, 0], &scope));
    assert!(futures_util::poll!(&mut first).is_pending());
    barrier.await.unwrap();
    let mut second = Box::pin(route.send(&[1, 1], &scope));
    assert!(futures_util::poll!(&mut second).is_pending());
    scope.seal();
    release.send(()).unwrap();
    first.await.unwrap();
    assert!(second.await.is_err());
    assert_eq!(writes.load(Ordering::Acquire), 1);
    member.retire();
    worker.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn direct_response_blocked_write_deadline_retires_socket_and_drops_queued_work() {
    let (member, route, recv) = route();
    let scope = DirectResponseScope::default();
    let (entered, barrier) = oneshot::channel();
    let (_release, gate) = oneshot::channel();
    let writes = Arc::new(AtomicUsize::new(0));
    let worker = tokio::spawn(worker(
        member.clone(),
        route.clone(),
        recv,
        Write {
            writes: writes.clone(),
            entered: Some(entered),
            release: Some(gate),
        },
    ));
    let mut first = Box::pin(route.send(&[1, 0], &scope));
    assert!(futures_util::poll!(&mut first).is_pending());
    barrier.await.unwrap();
    let mut second = Box::pin(route.send(&[1, 1], &scope));
    assert!(futures_util::poll!(&mut second).is_pending());
    tokio::time::advance(Duration::from_secs(5)).await;
    worker.await.unwrap();
    assert!(first.await.is_err());
    assert!(second.await.is_err());
    assert!(!member.is_current());
    assert_eq!(writes.load(Ordering::Acquire), 1);
}
