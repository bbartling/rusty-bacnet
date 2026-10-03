use super::{BipServerBuilder, ServerBuilder, TransportPort};
use bacnet_encoding::npdu::NpduAddress;
use bacnet_types::constructed::BACnetAddress;
use bacnet_types::error::Error;

/// A source address length a restriction entry can hold and match: 1 to
/// [`BACnetAddress::MAX_MAC_LEN`] octets. Every routed source and every
/// built-in transport's MAC fits that bound (#1141), so a longer entry could
/// never match anything (#1157).
fn address_length_fits(length: usize) -> bool {
    (1..=BACnetAddress::MAX_MAC_LEN).contains(&length)
}

/// Exact claimed DCC source, not an authenticated principal (including SC VMAC).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DccSource {
    /// Full link source MAC bytes, used only when no routed source is present.
    Direct(Vec<u8>),
    /// Full routed source network and address, independent of the immediate router.
    Routed {
        /// Claimed source network (1..=65534).
        network: u16,
        /// Complete claimed source address (1 to
        /// [`BACnetAddress::MAX_MAC_LEN`] octets).
        address: Vec<u8>,
    },
}

/// Validated static exact-source restriction. An empty list denies every source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DccSourceRestriction(Vec<DccSource>);

impl DccSourceRestriction {
    /// Accept at most 256 entries, each with 1 to
    /// [`BACnetAddress::MAX_MAC_LEN`] (18) address octets, the longest source
    /// address the network layer delivers (#1157). Routed networks must be
    /// 1..=65534. These are local configuration limits.
    pub fn new(sources: Vec<DccSource>) -> Result<Self, Error> {
        if sources.len() > 256 {
            return Err(Error::Encoding(
                "DCC source restriction allows at most 256 entries".into(),
            ));
        }
        for source in &sources {
            let address = match source {
                DccSource::Direct(address) => address,
                DccSource::Routed { network, address } => {
                    if !(1..=65534).contains(network) {
                        return Err(Error::Encoding(
                            "DCC routed source network must be 1..=65534".into(),
                        ));
                    }
                    address
                }
            };
            if !address_length_fits(address.len()) {
                return Err(Error::Encoding(format!(
                    "DCC source address must contain 1..={} octets",
                    BACnetAddress::MAX_MAC_LEN
                )));
            }
        }
        Ok(Self(sources))
    }

    /// Reject a configured restriction unless password-required policy is explicit.
    pub fn validate_policy(&self, policy: DccPolicy) -> Result<(), Error> {
        if policy != DccPolicy::RequirePassword {
            return Err(Error::Encoding(
                "DCC source restriction requires RequirePassword policy".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn allows(&self, mac: &[u8], routed: Option<&NpduAddress>) -> bool {
        // Never use the admission canonicalizer: its malformed routed fallback
        // is not an authorization identity. Compare all bytes, not telemetry.
        match routed {
            Some(source) => {
                (1..=65534).contains(&source.network)
                    && address_length_fits(source.mac_address.len())
                    && self.0.iter().any(|entry| matches!(entry,
                        DccSource::Routed { network, address }
                        if *network == source.network && address.as_slice() == source.mac_address.as_slice()))
            }
            None => address_length_fits(mac.len()) && self.0.iter().any(|entry|
                matches!(entry, DccSource::Direct(address) if address.as_slice() == mac)),
        }
    }
}

impl super::ServerConfig {
    pub(super) fn validate_dcc_config(&self) -> Result<(), Error> {
        self.dcc_policy.validate(&self.dcc_password)?;
        if let Some(restriction) = &self.dcc_source_restriction {
            restriction.validate_policy(self.dcc_policy)?;
        }
        if let Some(limit) = self.dcc_disable_rate_limit {
            limit.validate()?;
        }
        Ok(())
    }
}

/// Local DeviceCommunicationControl authorization, not source authentication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DccPolicy {
    /// Deny all valid DCC modes, even with a correct configured password.
    #[default]
    DenyAll,
    /// Allow supported modes only with a configured nonempty password.
    RequirePassword,
    /// INSECURE compatibility mode: preserve optional-password authorization.
    /// A configured password is still checked; absence permits any requester.
    LegacyPermissive,
}

impl DccPolicy {
    /// Validate operator configuration before transport startup or dialing.
    pub fn validate(self, password: &Option<String>) -> Result<(), Error> {
        if self == Self::RequirePassword && password.as_ref().is_none_or(String::is_empty) {
            return Err(Error::Encoding(
                "RequirePassword DCC policy requires a nonempty dcc_password".into(),
            ));
        }
        Ok(())
    }
}

impl<T: TransportPort + 'static> ServerBuilder<T> {
    /// Set the password required for DeviceCommunicationControl requests.
    pub fn dcc_password(mut self, password: impl Into<String>) -> Self {
        self.config.dcc_password = Some(password.into());
        self
    }

    /// Restrict claimed DCC sources; None preserves unrestricted policy behavior.
    pub fn dcc_source_restriction(mut self, restriction: Option<DccSourceRestriction>) -> Self {
        self.config.dcc_source_restriction = restriction;
        self
    }
    /// Select explicit local DCC authorization (default: deny all).
    pub fn dcc_policy(mut self, policy: DccPolicy) -> Self {
        self.config.dcc_policy = policy;
        self
    }
}

impl BipServerBuilder {
    /// Set the password required for DeviceCommunicationControl requests.
    pub fn dcc_password(mut self, password: impl Into<String>) -> Self {
        self.config.dcc_password = Some(password.into());
        self
    }

    /// Restrict claimed DCC sources; requires explicit RequirePassword policy.
    pub fn dcc_source_restriction(mut self, restriction: Option<DccSourceRestriction>) -> Self {
        self.config.dcc_source_restriction = restriction;
        self
    }
    /// Select explicit local DCC authorization (default: deny all).
    pub fn dcc_policy(mut self, policy: DccPolicy) -> Self {
        self.config.dcc_policy = policy;
        self
    }
}
