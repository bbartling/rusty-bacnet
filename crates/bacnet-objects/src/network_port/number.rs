//! One live number/quality pair; configured input remains in BipPortConfig.
/// Internal single-link number state shared by the nonrouter control owner.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkNumber {
    number: u16,
    quality: u8,
}
impl NetworkNumber {
    /// Initialize a new runtime from explicit local configuration only.
    #[doc(hidden)]
    pub fn configured(number: u16) -> Self {
        Self {
            number,
            quality: if number == 0 { 0 } else { 3 },
        }
    }
    /// Number and Clause 12.56 quality from the same state version.
    #[doc(hidden)]
    pub fn snapshot(self) -> (u16, u8) {
        (self.number, self.quality)
    }
    /// Apply Clause 6.4.15 precedence. Unusable values are local refusal policy.
    #[doc(hidden)]
    pub fn observe(&mut self, number: u16, flag: u8) {
        if number == 0 || number == u16::MAX || flag > 1 {
            return;
        }
        if self.quality == 3 {
            if flag == 1 && number != self.number {
                tracing::debug!(
                    configured = self.number,
                    announced = number,
                    "local Network Number configuration conflict"
                );
            }
            return;
        }
        if flag == 1 || self.quality < 2 {
            self.number = number;
            self.quality = if flag == 1 { 2 } else { 1 };
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_number_quality_precedence_and_numeric_policy() {
        let mut state = NetworkNumber::configured(0);
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
        let mut configured = NetworkNumber::configured(17);
        configured.observe(18, 1);
        configured.observe(19, 0);
        assert_eq!(configured.snapshot(), (17, 3));
        assert_eq!(NetworkNumber::configured(0).snapshot(), (0, 0));
    }
}
