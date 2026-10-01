//! The `BACnetDaysOfWeek` bit string.

use super::{pack_octet, unpack_octet};

bitflags::bitflags! {
    /// `BACnetDaysOfWeek` — 7-bit string with one bit per weekday, Monday
    /// first (Clause 21). A `BACnetDestination` uses it as `valid-days`.
    ///
    /// Bit *N* of the string is day *N*: `MONDAY` is bit 0 and `SUNDAY` is
    /// bit 6, the same bit0-first layout as
    /// [`EventTransitionBits`](super::EventTransitionBits).
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct DaysOfWeek: u8 {
        /// Monday (bit 0).
        const MONDAY = 1 << 0;
        /// Tuesday (bit 1).
        const TUESDAY = 1 << 1;
        /// Wednesday (bit 2).
        const WEDNESDAY = 1 << 2;
        /// Thursday (bit 3).
        const THURSDAY = 1 << 3;
        /// Friday (bit 4).
        const FRIDAY = 1 << 4;
        /// Saturday (bit 5).
        const SATURDAY = 1 << 5;
        /// Sunday (bit 6).
        const SUNDAY = 1 << 6;
    }
}

impl DaysOfWeek {
    /// Decode from a BACnet bit-string payload (MSB-first).
    ///
    /// Only the first octet's seven defined bits are read, so a peer's
    /// nonzero pad bit never reaches the value.
    pub fn from_bacnet(data: &[u8]) -> Self {
        Self::from_bits_truncate(unpack_octet(data, 7))
    }

    /// Encode to the single Clause 20.2.10 wire octet (`unused_bits: 1`):
    /// `MONDAY` at `0x80` through `SUNDAY` at `0x02`.
    pub fn to_bacnet(self) -> u8 {
        pack_octet(self.bits())
    }
}

impl_named_bit_display!(DaysOfWeek);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_of_week_msb_first() {
        // Asymmetric vectors: a reversed bit order would decode 0xC0 as
        // Saturday and Sunday, not Monday and Tuesday.
        assert_eq!(DaysOfWeek::MONDAY.to_bacnet(), 0x80);
        assert_eq!(DaysOfWeek::SUNDAY.to_bacnet(), 0x02);
        assert_eq!(DaysOfWeek::all().to_bacnet(), 0xFE);
        let days = DaysOfWeek::from_bacnet(&[0xC0]);
        assert_eq!(days, DaysOfWeek::MONDAY | DaysOfWeek::TUESDAY);
        assert_eq!(days.to_string(), "MONDAY | TUESDAY");
        assert_eq!(DaysOfWeek::from_bacnet(&[0xFE]), DaysOfWeek::all());
    }

    #[test]
    fn days_of_week_ignores_pad_bit_and_empty_payload() {
        assert_eq!(DaysOfWeek::from_bacnet(&[0xFF]), DaysOfWeek::all());
        assert_eq!(DaysOfWeek::from_bacnet(&[0x01]), DaysOfWeek::empty());
        assert_eq!(DaysOfWeek::from_bacnet(&[]), DaysOfWeek::empty());
        assert_eq!(DaysOfWeek::empty().to_string(), "()");
    }
}
