//! Pure single-link Network Number state and Clause 6.4.20 precedence.
/// One live number/quality pair. The default is UNKNOWN/zero.
/// Known numbers are always in 1..=65534; peer observations cannot create local configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkNumber {
    number: u16,
    quality: u8,
}
impl NetworkNumber {
    /// Initialize from explicit local configuration: zero is UNKNOWN.
    /// Returns `None` for reserved number 65535.
    pub const fn configured(number: u16) -> Option<Self> {
        if number == u16::MAX {
            return None;
        }
        Some(Self {
            number,
            quality: if number == 0 { 0 } else { 3 },
        })
    }
    /// Number and Clause 12.56 quality from the same state version.
    pub fn snapshot(self) -> (u16, u8) {
        (self.number, self.quality)
    }
    /// Apply Clause 6.4.20 precedence. Unusable values are local refusal policy.
    pub fn observe(&mut self, number: u16, flag: u8) -> Observation {
        if number == 0 || number == u16::MAX || flag > 1 {
            return Observation::Ignored;
        }
        if self.quality == 3 {
            return if flag == 1 && number != self.number {
                Observation::ConfiguredConflict
            } else {
                Observation::Ignored
            };
        }
        if flag == 1 || self.quality < 2 {
            self.number = number;
            self.quality = if flag == 1 { 2 } else { 1 };
            Observation::Applied
        } else {
            Observation::Ignored
        }
    }
}
/// Result of observing a peer announcement; logging belongs to the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observation {
    /// The announcement applied to the live pair.
    Applied,
    /// Invalid input or a lower-priority announcement left the pair unchanged.
    Ignored,
    /// A configured peer announced a different number from local configuration.
    ConfiguredConflict,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_number_quality_precedence_and_numeric_policy() {
        assert_eq!(NetworkNumber::configured(u16::MAX), None);
        let mut state = NetworkNumber::default();
        assert_eq!(state.snapshot(), (0, 0));
        for (number, flag, expected) in [
            (10, 0, (10, 1)),
            (11, 0, (11, 1)),
            (11, 1, (11, 2)),
            (11, 0, (11, 2)),
            (12, 0, (11, 2)),
            (12, 1, (12, 2)),
            (0, 1, (12, 2)),
            (65535, 1, (12, 2)),
            (15, 2, (12, 2)),
            (65534, 1, (65534, 2)),
            (1, 1, (1, 2)),
        ] {
            state.observe(number, flag);
            assert_eq!(state.snapshot(), expected);
        }
        let mut configured = NetworkNumber::configured(17).unwrap();
        assert_eq!(configured.observe(18, 1), Observation::ConfiguredConflict);
        configured.observe(19, 0);
        assert_eq!(configured.snapshot(), (17, 3));
        assert_eq!(NetworkNumber::configured(0).unwrap().snapshot(), (0, 0));
    }
}
