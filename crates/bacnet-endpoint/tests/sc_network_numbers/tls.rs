use bacnet_transport::{sc_hub::ScHubTlsConfig, sc_tls::ScNodeTlsConfig};
pub struct TestCa {
    pub hub_tls: ScHubTlsConfig,
    pub node_tls: ScNodeTlsConfig,
}

pub fn test_ca() -> TestCa {
    use rcgen::{CertificateParams, Issuer, KeyPair};
    use rustls::pki_types::PrivatePkcs8KeyDer;
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let hub_key = KeyPair::generate().unwrap();
    let hub_cert = CertificateParams::new(vec!["localhost".into(), "127.0.0.1".into()])
        .unwrap()
        .signed_by(&hub_key, &issuer)
        .unwrap();
    let hub_tls = ScHubTlsConfig::from_der(
        vec![ca_cert.der().clone()],
        vec![hub_cert.der().clone()],
        PrivatePkcs8KeyDer::from(hub_key.serialize_der()).into(),
    )
    .unwrap();

    let node_key = KeyPair::generate().unwrap();
    let node_cert =
        CertificateParams::new(vec!["node".into(), "localhost".into(), "127.0.0.1".into()])
            .unwrap()
            .signed_by(&node_key, &issuer)
            .unwrap();
    let node_tls = ScNodeTlsConfig::from_der(
        vec![ca_cert.der().clone()],
        vec![node_cert.der().clone()],
        PrivatePkcs8KeyDer::from(node_key.serialize_der()).into(),
    )
    .unwrap();

    TestCa { hub_tls, node_tls }
}
