use super::*;
use crate::sc_tls::boxed;
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::time::Duration;

pub(super) type ClientWs = WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

// Keep a paused Tokio clock from auto-advancing while real loopback I/O waits
// for the reactor. The wall-clock bound diagnoses a broken barrier.
pub(super) async fn poll_io<F: std::future::Future>(future: F) -> F::Output {
    tokio::pin!(future);
    let started = std::time::Instant::now();
    loop {
        if let std::task::Poll::Ready(value) = futures_util::poll!(&mut future) {
            return value;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "loopback/barrier did not complete"
        );
        tokio::task::yield_now().await;
    }
}

pub(super) async fn until(predicate: impl Fn() -> bool) {
    poll_io(async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await;
}

pub(super) fn request(vmac: Vmac, uuid: DeviceUuid) -> Message {
    let mut wire = crate::sc_frame::connect_test_support::valid_connect(6, vmac);
    wire[10..26].copy_from_slice(&uuid);
    Message::Binary(wire.into())
}

pub(super) struct DeadlinePeer {
    pub ws: ClientWs,
    pub sink: Arc<Mutex<WsSink>>,
    pub deadline: Arc<super::deadlines::ConnectDeadline>,
    pub task: JoinHandle<()>,
    pub active: Arc<std::sync::atomic::AtomicUsize>,
}

impl DeadlinePeer {
    pub async fn new(clients: Clients, duration: Duration) -> Self {
        let (server, ws, address, accepted) = TestTls::new().pair().await;
        let verified_leaf = super::certificate_bindings::VerifiedLeaf::from_verified_chain(
            server.get_ref().get_ref().1.peer_certificates(),
        );
        let (write, read) = server.split();
        let sink = Arc::new(Mutex::new(write));
        let deadline = Arc::new(super::deadlines::ConnectDeadline::new(accepted + duration));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let admission = super::connection::Admission::new(active.clone(), Duration::from_secs(10));
        // Direct-harness pair performs real mutual TLS with a CA-verified
        // client certificate; only the accept-loop path is bypassed.
        let runtime = Arc::new(super::admission::AdmissionRuntime::default());
        let operation = super::deadlines::serve(
            super::context::PeerConnection {
                addr: address,
                read,
                write: sink.clone(),
                verified_leaf,
            },
            super::context::HubConnectionContext {
                hub: ([0x10; 6], [0x10; 16]),
                clients,
                admission: runtime,
                graceful: super::tasks::Tasks::new().graceful_ctx(),
                timing: super::timing::HubTiming::new(super::ScHubProbePolicy::default()),
            },
            deadline.clone(),
            || {},
        );
        let task = tokio::spawn(async move {
            let _admission = admission;
            operation.await;
        });
        Self {
            ws,
            sink,
            deadline,
            task,
            active,
        }
    }

    pub async fn next(&mut self) -> Message {
        poll_io(self.ws.next()).await.unwrap().unwrap()
    }
}

impl Drop for DeadlinePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct TestTls {
    pub acceptor: TlsAcceptor,
    pub hub_config: ScHubTlsConfig,
    pub client: Arc<rustls::ClientConfig>,
    pub node: crate::sc_tls::ScNodeTlsConfig,
}

impl TestTls {
    pub async fn pair(
        &self,
    ) -> (
        WebSocketStream<TlsStream>,
        ClientWs,
        SocketAddr,
        tokio::time::Instant,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        // The handshakes are boxed here and in `websocket`: tests poll on a
        // 2 MiB test thread, and unboxed, these futures put about 100 KB more
        // in each caller's frame (#953).
        let server = boxed(|| async {
            let (tcp, peer) = listener.accept().await.unwrap();
            crate::sc_tls::disable_nagle(&tcp); // as the hub's accept does
            let tls = self.acceptor.accept(tcp).await.unwrap();
            #[allow(clippy::result_large_err)]
            let ws = tokio_tungstenite::accept_hdr_async(tls, |_: &_, mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                response.headers_mut().insert("Sec-WebSocket-Protocol", crate::sc_frame::BACNET_SC_HUB_SUBPROTOCOL.parse().unwrap());
                Ok(response)
            }).await.unwrap();
            (ws, peer, tokio::time::Instant::now())
        });
        let ((server, peer, accepted), client) =
            tokio::join!(server, boxed(|| self.websocket(address)));
        (server, client, peer, accepted)
    }

    pub async fn websocket(
        &self,
        address: SocketAddr,
    ) -> WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        let tls = boxed(|| self.connect_tls(tcp)).await;
        let request = tokio_tungstenite::tungstenite::client::ClientRequestBuilder::new(
            format!("wss://localhost:{}", address.port())
                .parse()
                .unwrap(),
        )
        .with_sub_protocol(crate::sc_frame::BACNET_SC_HUB_SUBPROTOCOL);
        boxed(|| tokio_tungstenite::client_async(request, tls))
            .await
            .unwrap()
            .0
    }

    pub async fn connect_tls(
        &self,
        tcp: tokio::net::TcpStream,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        // Like production SC sockets (#900): with Nagle on, a test that sends
        // two messages before reading waits on the hub's delayed ACK.
        tcp.set_nodelay(true).unwrap();
        tokio_rustls::TlsConnector::from(self.client.clone())
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap()
    }

    pub fn new() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_key = KeyPair::generate().unwrap();
        let server_cert = CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let client_key = KeyPair::generate().unwrap();
        let client_cert = CertificateParams::new(vec!["bacnet-client".into()])
            .unwrap()
            .signed_by(&client_key, &issuer)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots.clone()))
            .build()
            .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![client_cert.der().clone()],
                PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
            )
            .unwrap();
        Self {
            acceptor: TlsAcceptor::from(Arc::new(server)),
            hub_config: ScHubTlsConfig::from_der(
                vec![ca_cert.der().clone()],
                vec![server_cert.der().clone()],
                PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
            )
            .unwrap(),
            client: Arc::new(client),
            node: crate::sc_tls::ScNodeTlsConfig::from_der(
                vec![ca_cert.der().clone()],
                vec![client_cert.der().clone()],
                PrivatePkcs8KeyDer::from(client_key.serialize_der()).into(),
            )
            .unwrap(),
        }
    }
}

/// Raises this process's soft descriptor limit so a test can hold `needed`
/// sockets at once. The limit is process-wide and libtest runs sibling tests
/// in the same process, so headroom is reserved for them too. A hard limit
/// that is too low fails here instead of as EMFILE in some later socket call.
#[cfg(unix)]
#[allow(unsafe_code)]
pub(super) fn reserve_descriptors(needed: libc::rlim_t) {
    const SIBLING_HEADROOM: libc::rlim_t = 1024;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the rlimit it is given.
    let read = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    assert_eq!(read, 0, "{}", std::io::Error::last_os_error());
    let wanted = needed.saturating_add(SIBLING_HEADROOM);
    if limit.rlim_cur >= wanted {
        return;
    }
    limit.rlim_cur = wanted.min(limit.rlim_max);
    // SAFETY: setrlimit only reads the rlimit it is given. Raising the soft
    // limit up to the hard limit needs no privilege.
    let raised = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    assert_eq!(raised, 0, "{}", std::io::Error::last_os_error());
    assert!(
        limit.rlim_cur >= needed,
        "test needs {needed} descriptors but the hard limit is {}",
        limit.rlim_max
    );
}

#[cfg(not(unix))]
pub(super) fn reserve_descriptors(_needed: u64) {}
