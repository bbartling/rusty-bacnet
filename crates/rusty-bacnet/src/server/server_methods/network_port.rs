use super::super::*;
use bacnet_objects::network_port::{BipPortConfig, NetworkPortObject};

#[pymethods]
impl BACnetServer {
    /// Add a configured, unbound IPV4/NORMAL application Network Port snapshot.
    /// Configuration is read-only; this does not bind or inspect a socket.
    #[pyo3(signature = (instance, name, *, ip_address="0.0.0.0", udp_port=47808, network_number=0, apdu_length=1476, subnet_mask="0.0.0.0", default_gateway="0.0.0.0", dns_servers=None))]
    fn add_bip_network_port(
        &self,
        instance: u32,
        name: &str,
        ip_address: &str,
        udp_port: u16,
        network_number: u16,
        apdu_length: u32,
        subnet_mask: &str,
        default_gateway: &str,
        dns_servers: Option<Vec<String>>,
    ) -> PyResult<()> {
        let address = |text: &str| -> PyResult<[u8; 4]> {
            text.parse::<std::net::Ipv4Addr>()
                .map(|ip| ip.octets())
                .map_err(|_| pyo3::exceptions::PyValueError::new_err("expected an IPv4 address"))
        };
        let dns_servers = match dns_servers {
            Some(values) => values
                .iter()
                .map(|s| address(s))
                .collect::<PyResult<Vec<_>>>()?,
            None => vec![[0; 4]],
        };
        let config = BipPortConfig {
            network_number,
            apdu_length,
            ip_address: address(ip_address)?,
            udp_port,
            subnet_mask: address(subnet_mask)?,
            default_gateway: address(default_gateway)?,
            dns_servers,
        };
        let obj = NetworkPortObject::new_bip(instance, name, config).map_err(to_py_err)?;
        self.push_pending(Box::new(obj))
    }
}
