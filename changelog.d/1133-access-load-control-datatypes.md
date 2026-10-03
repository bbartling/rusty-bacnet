---
section: Fixed
---
- **Breaking Credential Data Input, Access Point and Load Control datatypes
  (wire and Rust API):** five rows now go out in the Clause 21 datatype their
  Clause 12 table gives them (#1133).
  - Load Control Requested_Shed_Level, Expected_Shed_Level and
    Actual_Shed_Level are BACnetShedLevel choices: percent `[0]`, level `[1]`
    or amount `[2]`. They went out as an application-tagged Unsigned or REAL,
    and started at percent 0, the deepest shed; they now start at level 0,
    which means no shed.
  - A WriteProperty of Requested_Shed_Level now takes that choice, which a
    client sending the standard form had been refused with INVALID_DATA_TYPE.
    Any other form, including the one-element list accepted before, fails with
    PROPERTY / INVALID_DATA_TYPE, and a percent above 100 or an amount that is
    negative or not finite with PROPERTY / VALUE_OUT_OF_RANGE. Since the object
    stays SHED_INACTIVE, an accepted write resets Expected_Shed_Level and
    Actual_Shed_Level to the Table 12-33 default of the written choice.
  - Access Point Access_Event_Time and Credential Data Input Update_Time are
    BACnetTimeStamp values; they went out as an application Date followed by
    a Time. Credential Data Input Present_Value is a
    BACnetAuthenticationFactor; it was a placeholder Enumerated. The
    SubscribeCOV reports carry the same forms.
  - Rust API: `BACnetShedLevel::Percent` and `Level` hold a `u64`; new
    `encode_shed_level` and `decode_shed_level` in
    `bacnet_encoding::constructed`; `LoadControlObject::set_requested_shed_level`
    and `set_actual_shed_level` return `Result`, the second refusing a choice
    other than the requested one; `AccessPointObject::set_access_event` takes a
    `BACnetTimeStamp`; and `CredentialDataInputObject::set_present_value`
    records a factor with its Update_Time, replacing `set_update_time`.
