//! Trusted single-port attachment; network writes never receive this authority.
use super::*;
use std::sync::Arc;

impl NetworkPortObject {
    pub(crate) fn network_number_internal(
        &mut self,
        announcement: Option<(u16, u8)>,
    ) -> NetworkNumber {
        if let Some((number, flag)) = announcement {
            self.network_number.observe(number, flag);
        }
        self.network_number
    }

    /// Borrow the complete configured B/IP snapshot.
    pub(crate) fn configuration_internal(&self) -> Option<&BipPortConfig> {
        self.bip.as_ref()
    }

    /// Reserve the built-in object for a live owner.
    pub(crate) fn reserve_internal(&mut self, lease: &Arc<()>) -> Result<(), Error> {
        if self.is_bound() || self.out_of_service || self.bip.is_none() {
            return Err(Error::Encoding(
                "Network Port is unavailable for NORMAL B/IP registration".into(),
            ));
        }
        self.network_number =
            NetworkNumber::configured(self.bip.as_ref().expect("validated B/IP").network_number);
        self.binding = Arc::downgrade(lease);
        Ok(())
    }

    /// Publish the matching owner's actual bind and supported capacity.
    pub(crate) fn reconcile_internal(
        &mut self,
        lease: &Arc<()>,
        ip: [u8; 4],
        udp: u16,
        capacity: u32,
    ) -> Result<(), Error> {
        if !self
            .binding
            .upgrade()
            .is_some_and(|current| Arc::ptr_eq(&current, lease))
        {
            return Err(Error::Encoding(
                "Network Port registration owner mismatch".into(),
            ));
        }
        let mut config = self
            .bip
            .clone()
            .ok_or_else(|| Error::Encoding("not B/IP".into()))?;
        config.ip_address = ip;
        config.udp_port = udp;
        config.apdu_length = capacity;
        config.validate(self.oid.instance_number())?;
        self.network_number = NetworkNumber::configured(config.network_number);
        self.apdu_length = capacity;
        self.mac_address = MacAddr::from_slice(&ip);
        self.mac_address.extend_from_slice(&udp.to_be_bytes());
        self.bip = Some(config);
        Ok(())
    }
}

impl NetworkPortObject {
    pub(super) fn is_bound(&self) -> bool {
        self.binding.strong_count() != 0
    }
}
