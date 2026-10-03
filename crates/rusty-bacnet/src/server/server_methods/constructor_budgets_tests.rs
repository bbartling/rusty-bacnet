use super::*;

use bacnet_types::constructed::BACnetAddress;

/// The `dcc_*` keywords with a required password and `entries` as the source
/// restriction.
fn restriction(entries: Vec<(Option<u16>, Vec<u8>)>) -> PyResult<DccConfiguration> {
    dcc_configuration(
        "require_password",
        &Some("required".into()),
        Some(entries),
        None,
    )
}

#[test]
fn dcc_source_restriction_entries_hold_to_the_bacnet_address_bound() {
    // #1157: the constructor accepts an entry of up to 18 octets
    // (BACnetAddress::MAX_MAC_LEN) and raises ValueError for one more.
    Python::initialize();
    let longest = BACnetAddress::MAX_MAC_LEN;
    for network in [None, Some(7)] {
        let accepted = restriction(vec![(network, vec![0x2a; longest])]).unwrap();
        assert!(accepted.source_restriction.is_some());
        let error = restriction(vec![(network, vec![0x2a; longest + 1])])
            .err()
            .expect("19-octet entry");
        Python::attach(|py| {
            assert!(error.is_instance_of::<PyValueError>(py));
            assert!(error.to_string().contains("DCC source address"), "{error}");
        });
    }
}
