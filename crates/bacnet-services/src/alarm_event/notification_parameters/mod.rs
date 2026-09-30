use super::property_states::{
    decode_device_obj_prop_ref, decode_property_states, encode_property_states, extract_raw_context,
};
use super::*;

mod decode;
mod decode_helpers;
mod decode_timer;
mod encode;
mod structured;

// ---------------------------------------------------------------------------
// NotificationParameters
// ---------------------------------------------------------------------------

/// Notification parameter variants for eventValues.
#[derive(Debug, Clone, PartialEq)]
pub enum NotificationParameters {
    /// [0] Change of bitstring.
    ChangeOfBitstring {
        /// Monitored bitstring value as `(unused_bits, data)`.
        referenced_bitstring: (u8, Vec<u8>),
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
    },
    /// [1] Change of state.
    ChangeOfState {
        /// New BACnetPropertyStates value that triggered the notification.
        new_state: BACnetPropertyStates,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
    },
    /// [2] Change of value.
    ChangeOfValue {
        /// New value (changed bits or a REAL) that triggered the notification.
        new_value: ChangeOfValueChoice,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
    },
    /// [3] Command failure. Value byte vectors contain encoded BACnet TLVs.
    CommandFailure {
        /// Commanded value as encoded BACnet bytes.
        command_value: Vec<u8>,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Feedback value that disagreed with the command, as encoded BACnet bytes.
        feedback_value: Vec<u8>,
    },
    /// [4] Floating limit.
    FloatingLimit {
        /// Current value of the monitored reference property.
        reference_value: f32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Setpoint the reference value is tracked against.
        setpoint_value: f32,
        /// Differential limit (distance from the setpoint) that was exceeded.
        error_limit: f32,
    },
    /// [5] Out of range.
    OutOfRange {
        /// Monitored value that crossed a limit.
        exceeding_value: f32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Deadband applied to the limit comparison, in the monitored value's units.
        deadband: f32,
        /// The limit that was exceeded, in the monitored value's units.
        exceeded_limit: f32,
    },
    /// [6] Complex event type.
    ComplexEventType {
        /// Reported property values; each holds encoded BACnet bytes and an optional priority.
        property_values: Vec<BACnetPropertyValue>,
    },
    /// [8] Change of life safety.
    ChangeOfLifeSafety {
        /// BACnetLifeSafetyState value the object entered (raw enumeration).
        new_state: u32,
        /// BACnetLifeSafetyMode value in effect (raw enumeration).
        new_mode: u32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// BACnetLifeSafetyOperation the object expects from an operator (raw enumeration).
        operation_expected: u32,
    },
    /// [9] Extended (vendor-defined). `parameters` contains encoded BACnet TLVs.
    Extended {
        /// Vendor identifier that defines the extended event type.
        vendor_id: u16,
        /// Vendor-specific extended event type number.
        extended_event_type: u32,
        /// Vendor-defined parameters as encoded BACnet bytes.
        parameters: Vec<u8>,
    },
    /// [10] Buffer ready.
    BufferReady {
        /// Reference to the log buffer property that has records ready.
        buffer_property: BACnetDeviceObjectPropertyReference,
        /// Total record count at the previous notification for this buffer.
        previous_notification: u32,
        /// Total record count now.
        current_notification: u32,
    },
    /// [11] Unsigned range.
    UnsignedRange {
        /// Monitored value that crossed a limit.
        exceeding_value: u64,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// The limit that was exceeded.
        exceeded_limit: u64,
    },
    /// [13] Access event. Authentication-factor bytes contain its three inner context fields.
    AccessEvent {
        /// BACnetAccessEvent value describing what happened (raw enumeration).
        access_event: u32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Counter distinguishing access events, carried as the `access-event-tag` field.
        access_event_tag: u32,
        /// Date and time at which the access event occurred.
        access_event_time: (Date, Time),
        /// Credential object (with optional device) that was presented.
        access_credential: BACnetDeviceObjectReference,
        /// Optional authentication factor as encoded BACnet bytes; `None` when absent.
        authentication_factor: Option<Vec<u8>>,
    },
    /// [14] Double out of range.
    DoubleOutOfRange {
        /// Monitored value that crossed a limit.
        exceeding_value: f64,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Deadband applied to the limit comparison, in the monitored value's units.
        deadband: f64,
        /// The limit that was exceeded, in the monitored value's units.
        exceeded_limit: f64,
    },
    /// [15] Signed out of range.
    SignedOutOfRange {
        /// Monitored value that crossed a limit.
        exceeding_value: i32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Deadband applied to the limit comparison (unsigned).
        deadband: u64,
        /// The limit that was exceeded.
        exceeded_limit: i32,
    },
    /// [16] Unsigned out of range.
    UnsignedOutOfRange {
        /// Monitored value that crossed a limit.
        exceeding_value: u64,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Deadband applied to the limit comparison.
        deadband: u64,
        /// The limit that was exceeded.
        exceeded_limit: u64,
    },
    /// [17] Change of characterstring.
    ChangeOfCharacterstring {
        /// New value of the monitored character string.
        changed_value: String,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Character-string value that is configured to count as alarming.
        alarm_value: String,
    },
    /// [18] Change of status flags. `present_value` preserves absent and present-empty context [0].
    ChangeOfStatusFlags {
        /// Present value as encoded BACnet bytes; `None` when the field is absent.
        present_value: Option<Vec<u8>>,
        /// Status flags of the referenced object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        referenced_flags: u8,
    },
    /// [19] Change of reliability. `property_values` contains encoded BACnet TLVs.
    ChangeOfReliability {
        /// BACnetReliability value that triggered the notification (raw enumeration).
        reliability: u32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Properties relevant to the reliability change, as encoded BACnet bytes.
        property_values: Vec<u8>,
    },
    /// [21] Change of discrete value. `new_value` contains encoded BACnet TLVs.
    ChangeOfDiscreteValue {
        /// New discrete value as encoded BACnet bytes.
        new_value: Vec<u8>,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
    },
    /// [22] Change of timer.
    ChangeOfTimer {
        /// BACnetTimerState value the timer entered (raw enumeration).
        new_state: u32,
        /// Status flags of the monitored object (4-bit BACnetStatusFlags, in-alarm = 0x08).
        status_flags: u8,
        /// Date and time of the timer update.
        update_time: (Date, Time),
        /// BACnetTimerTransition of the last state change (raw enumeration); `None` when absent.
        last_state_change: Option<u32>,
        /// Initial timeout configured for the timer; `None` when absent.
        initial_timeout: Option<u32>,
        /// Date and time when the timer expires; `None` when absent.
        expiration_time: Option<(Date, Time)>,
    },
}

/// CHOICE within ChangeOfValue notification parameters.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeOfValueChoice {
    /// Bitstring value that changed.
    ChangedBits {
        /// Number of unused trailing bits in the last byte of `data`.
        unused_bits: u8,
        /// Bitstring content bytes.
        data: Vec<u8>,
    },
    /// REAL value that changed.
    ChangedValue(f32),
}
