//! Shared in-memory harness for the RB-03 router envelope test modules.
//!
//! No sockets, no timing. [`Harness::handle`] exercises the local-control
//! admission point; [`Harness::dispatch`] exercises the routing-first
//! dispatcher. Both test modules build ingress contexts here so discovery
//! and control-envelope coverage stays in lockstep.

use super::*;
use bacnet_transport::port::TransportProvenance;

pub(super) fn control_npdu(message_type: NetworkMessageType, payload: &[u8]) -> Npdu {
    Npdu {
        is_network_message: true,
        message_type: Some(message_type.to_raw()),
        payload: Bytes::copy_from_slice(payload),
        ..Npdu::default()
    }
}

pub(super) fn attributes() -> Vec<DataAttribute> {
    vec![DataAttribute {
        option_type: 31,
        must_understand: false,
        data: vec![0x12, 0x34],
    }]
}

pub(super) struct Harness {
    pub(super) table: Arc<Mutex<RouterTable>>,
    pub(super) discovery: Arc<Mutex<super::DiscoveryTracker>>,
    pub(super) txs: Vec<mpsc::Sender<SendRequest>>,
    pub(super) rxs: Vec<mpsc::Receiver<SendRequest>>,
    pub(super) gate: Arc<super::control_policy::ControlGate>,
    /// The router's own network-control consumer, absent until
    /// [`Self::network_control`] installs one.
    pub(super) local: LocalControl,
}

/// The harness router's own MAC on each port: [1] on 1000, [2] on 2000.
pub(super) const PORT_MACS: [u8; 2] = [0x01, 0x02];

/// The harness router's own address on each port.
pub(super) fn own_addresses() -> OwnAddresses {
    let addresses = [1000, 2000]
        .into_iter()
        .zip(PORT_MACS)
        .map(|(network, mac)| NpduAddress {
            network,
            mac_address: MacAddr::from_slice(&[mac]),
        })
        .collect();
    OwnAddresses::new(addresses)
}

fn local_control(tx: Option<AdmissionSender<ReceivedNetworkControl>>) -> LocalControl {
    LocalControl::new(own_addresses(), tx, Arc::default())
}

impl Harness {
    pub(super) fn two_port() -> Self {
        let mut table = RouterTable::new();
        table.add_direct(1000, 0);
        table.add_direct(2000, 1);
        Self::with_table(table)
    }

    pub(super) fn with_table(table: RouterTable) -> Self {
        Self::with_gate(
            table,
            Arc::new(super::control_policy::ControlGate::permissive()),
        )
    }

    pub(super) fn with_gate(
        table: RouterTable,
        gate: Arc<super::control_policy::ControlGate>,
    ) -> Self {
        let (tx0, rx0) = mpsc::channel(16);
        let (tx1, rx1) = mpsc::channel(16);
        Self {
            table: Arc::new(Mutex::new(table)),
            discovery: Arc::new(Mutex::new(super::DiscoveryTracker::default())),
            txs: vec![tx0, tx1],
            rxs: vec![rx0, rx1],
            gate,
            local: local_control(None),
        }
    }

    /// Give the router a network-control consumer and return its receiver.
    pub(super) fn network_control(&mut self) -> mpsc::Receiver<ReceivedNetworkControl> {
        let (tx, rx, _) = AdmissionReceiver::channel(false);
        self.local = local_control(Some(tx));
        rx
    }

    /// RB-04 multi-peer fixture: direct 1000/0 + 2000/1, plus learned routes
    /// across three distinct ingress peers — 3000/3001 via port 1 peer [2],
    /// 4000 via port 1 peer [3] (same port, other peer), 5000 via port 0
    /// peer [9] (other port). Lets omitted/single/mixed Busy/Available lists
    /// assert per-route change AND no-change on one topology.
    pub(super) fn busy_scope() -> Self {
        let mut table = RouterTable::new();
        table.add_direct(1000, 0);
        table.add_direct(2000, 1);
        table.add_learned(3000, 1, MacAddr::from_slice(&[2]));
        table.add_learned(3001, 1, MacAddr::from_slice(&[2]));
        table.add_learned(4000, 1, MacAddr::from_slice(&[3]));
        table.add_learned(5000, 0, MacAddr::from_slice(&[9]));
        Self::with_table(table)
    }

    pub(super) fn ctx(&self, port: usize, source_mac: &[u8], npdu: Npdu) -> IngressContext {
        self.ctx_with_provenance(port, source_mac, npdu, TransportProvenance::unverified())
    }

    pub(super) fn ctx_with_provenance(
        &self,
        port: usize,
        source_mac: &[u8],
        npdu: Npdu,
        provenance: TransportProvenance,
    ) -> IngressContext {
        let _ = &self;
        IngressContext {
            port_idx: port,
            port_network: if port == 0 { 1000 } else { 2000 },
            source_mac: MacAddr::from_slice(source_mac),
            link_layer_group: true,
            data_attributes: Vec::new(),
            provenance,
            npdu,
        }
    }

    pub(super) async fn handle(&mut self, ctx: IngressContext) {
        handle_network_message(&self.table, &self.txs, &ctx, &self.gate, &self.local).await;
    }

    pub(super) async fn dispatch(&mut self, ctx: IngressContext) {
        dispatch_network_message(
            &self.table,
            &self.discovery,
            &self.txs,
            &ctx,
            &self.gate,
            &self.local,
        )
        .await;
    }

    pub(super) fn drain(&mut self, port: usize) -> Vec<SendRequest> {
        let mut out = Vec::new();
        while let Ok(req) = self.rxs[port].try_recv() {
            out.push(req);
        }
        out
    }

    pub(super) fn assert_quiet(&mut self) {
        for port in 0..self.rxs.len() {
            assert!(
                self.rxs[port].try_recv().is_err(),
                "expected no output on port {port}"
            );
        }
    }
}

pub(super) fn broadcast_data(requests: Vec<SendRequest>) -> Vec<Bytes> {
    requests
        .into_iter()
        .map(|req| match req {
            SendRequest::Broadcast { npdu, .. } => npdu,
            SendRequest::Unicast { .. } => panic!("expected broadcast"),
        })
        .collect()
}
