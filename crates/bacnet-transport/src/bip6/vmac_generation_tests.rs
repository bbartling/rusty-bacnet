use std::net::Ipv6Addr;

use super::{generate_random_vmac, Bip6Transport, Bip6Vmac, MAX_VMAC_RETRIES};
use crate::port::TransportPort;

#[test]
fn generate_random_vmac_produces_3_bytes() {
    let vmac = generate_random_vmac().unwrap();
    assert_eq!(vmac.len(), 3);
    assert_eq!(vmac[0] & 0xC0, 0x40);
}

#[test]
fn generate_random_vmac_is_nondeterministic() {
    let vmacs: Vec<Bip6Vmac> = (0..10).map(|_| generate_random_vmac().unwrap()).collect();
    let all_same = vmacs.windows(2).all(|window| window[0] == window[1]);
    assert!(!all_same, "10 random VMACs should not all be identical");
}

#[tokio::test]
async fn out_of_range_device_instance_fails_before_bip6_startup() {
    let mut transport = Bip6Transport::new(Ipv6Addr::LOCALHOST, 0, Some(0x40_0000));
    assert!(transport.start().await.is_err());
}

#[test]
fn max_vmac_retries_constant() {
    const { assert!(MAX_VMAC_RETRIES >= 1, "must allow at least one retry") };
}
