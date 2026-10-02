//! The transport of a built client, and the BBMD helpers that reach through it.

use bacnet_transport::bbmd::{BdtEntry, FdtEntryWire};
use bacnet_transport::bip::AsBip;
use bacnet_types::enums::BvlcResultCode;

use super::*;

impl<T: TransportPort + 'static> BACnetClient<T> {
    /// The transport this client was built with.
    ///
    /// Use it for transport state and diagnostics after `build()`: the
    /// BACnet/SC connection-state watch and NPDU drop counts, the B/IP
    /// management, FDT and fanout counters and BBMD state, or an MS/TP
    /// [`diagnostics()`](bacnet_transport::mstp::MstpTransport::diagnostics)
    /// handle.
    ///
    /// The client keeps its transport inside the network layer that its
    /// dispatch task shares, so it lends a borrow and never gives the
    /// transport up. What you take from the borrow can outlive it. The SC
    /// watch receiver, an MS/TP diagnostics handle and the BBMD state `Arc`
    /// are owned, so a long-lived UI takes them once and moves them into its
    /// own tasks, as MS/TP callers already do before handing the transport
    /// over. Counters are cheap snapshots: poll them through this borrow as
    /// often as the UI redraws. The borrow is shared, so the transport's
    /// `start` and `stop` stay with the client.
    ///
    /// This is one accessor for every transport, rather than a bundle of
    /// handles returned by each builder. Each transport already offers its
    /// diagnostics on `&self`, so nothing new is needed per transport, and
    /// clients from [`generic_builder`](Self::generic_builder) get the same
    /// access. Sharing the transport through an `Arc` was ruled out too:
    /// [`stop`](Self::stop) needs sole ownership of the network layer to stop
    /// the transport, which an outstanding clone would block.
    ///
    /// ```
    /// use std::net::Ipv4Addr;
    /// use bacnet_client::client::BACnetClient;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    /// runtime.block_on(Box::pin(async {
    ///     let mut client = BACnetClient::bip_builder()
    ///         .interface(Ipv4Addr::LOCALHOST)
    ///         .port(0)
    ///         .build()
    ///         .await?;
    ///     // Counter snapshots: poll them whenever the UI redraws.
    ///     let counters = client.transport().management_counters();
    ///     assert_eq!(counters.read_bdt_responses, 0);
    ///     assert_eq!(client.transport().fanout_counters().packets_forwarded, 0);
    ///     // This client is not a BBMD, so it has no BBMD state or FDT.
    ///     assert!(client.transport().bbmd_state().is_none());
    ///     assert!(client.transport().fdt_counters().await.is_none());
    ///     client.stop().await?;
    ///     Ok::<_, bacnet_types::error::Error>(())
    /// }))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn transport(&self) -> &T {
        self.network.transport()
    }
}

/// BBMD management helpers (Annex J), for a client whose transport is B/IP.
///
/// They work on a client over [`BipTransport`], and on one over
/// [`AnyTransport`](bacnet_transport::any::AnyTransport) when its variant is
/// `Bip`. On any other variant each returns
/// [`Error::UnsupportedTransport`] before sending anything.
///
/// ```
/// use bacnet_client::client::BACnetClient;
/// use bacnet_transport::any::AnyTransport;
/// use bacnet_transport::loopback::LoopbackTransport;
/// use bacnet_transport::mstp::NoSerial;
/// use bacnet_types::error::Error;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
/// runtime.block_on(Box::pin(async {
///     let (ours, _peer) = LoopbackTransport::pair(vec![1], vec![2]);
///     let mut client = BACnetClient::generic_builder()
///         .transport(AnyTransport::<NoSerial>::Loopback(ours))
///         .build()
///         .await?;
///     let bbmd = [127, 0, 0, 1, 0xBA, 0xC0];
///     assert!(matches!(
///         client.read_bdt(&bbmd).await,
///         Err(Error::UnsupportedTransport { required: "BACnet/IP", actual: "loopback" })
///     ));
///     client.stop().await?;
///     Ok::<_, Error>(())
/// }))?;
/// # Ok(())
/// # }
/// ```
impl<T: TransportPort + AsBip + 'static> BACnetClient<T> {
    /// Read the Broadcast Distribution Table from a BBMD.
    pub async fn read_bdt(&self, target: &[u8]) -> Result<Vec<BdtEntry>, Error> {
        self.transport().as_bip()?.read_bdt(target).await
    }

    /// Write the Broadcast Distribution Table to a BBMD.
    ///
    /// A BBMD that follows the 2020 standard answers with the not-supported
    /// result and keeps its table.
    pub async fn write_bdt(
        &self,
        target: &[u8],
        entries: &[BdtEntry],
    ) -> Result<BvlcResultCode, Error> {
        self.transport().as_bip()?.write_bdt(target, entries).await
    }

    /// Read the Foreign Device Table from a BBMD.
    pub async fn read_fdt(&self, target: &[u8]) -> Result<Vec<FdtEntryWire>, Error> {
        self.transport().as_bip()?.read_fdt(target).await
    }

    /// Delete a Foreign Device Table entry on a BBMD.
    pub async fn delete_fdt_entry(
        &self,
        target: &[u8],
        ip: [u8; 4],
        port: u16,
    ) -> Result<BvlcResultCode, Error> {
        self.transport()
            .as_bip()?
            .delete_fdt_entry(target, ip, port)
            .await
    }

    /// Register as a foreign device with a BBMD and return the result code.
    ///
    /// This sends one registration. It does not make the transport a
    /// foreign device for broadcasts or renew the registration.
    pub async fn register_foreign_device_bvlc(
        &self,
        target: &[u8],
        ttl: u16,
    ) -> Result<BvlcResultCode, Error> {
        self.transport()
            .as_bip()?
            .register_foreign_device_bvlc(target, ttl)
            .await
    }
}
