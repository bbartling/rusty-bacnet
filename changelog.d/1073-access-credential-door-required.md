---
section: Changed
---
- **Breaking Access Credential and Access Door required properties (wire and
  Rust API):** both objects now serve every row their property tables mark
  required (#1073).
  - Access Credential (Clause 12.35, Table 12-40) gains Global_Identifier
    (writable Unsigned32; a value past 32 bits is VALUE_OUT_OF_RANGE),
    Reason_For_Disable, Activation_Time, Expiration_Time and
    Credential_Disable. Credential_Status is now worked out from
    Reason_For_Disable, INACTIVE while the list has anything in it and ACTIVE
    otherwise, so it is read-only: a WriteProperty that used to set it now
    fails with WRITE_ACCESS_DENIED, and a new credential reads ACTIVE instead
    of INACTIVE. The list joins three sources: reasons the application raises
    with the new `add_disable_reason` (and withdraws with
    `remove_disable_reason`), the reason the current Credential_Disable value
    stands for (DISABLED, DISABLED_MANUAL or DISABLED_LOCKOUT; a vendor value
    stands for DISABLED), and DISABLED_NOT_YET_ACTIVE or DISABLED_EXPIRED,
    judged against the database clock on every read. With no usable clock
    frame the window adds nothing. Credential_Disable takes the four named
    values and 64 to 65535; Activation_Time and Expiration_Time take a
    specific date and time, or all X'FF' for an open end, and refuse a partly
    specified one with VALUE_OUT_OF_RANGE.
  - Assigned_Access_Rights used to read as an Unsigned count and
    Authentication_Factors as a list of octet strings. They are now
    BACnetARRAYs of BACnetAssignedAccessRights and
    BACnetCredentialAuthenticationFactor, readable whole, by element or by
    size, and set through `set_assigned_access_rights` and
    `set_authentication_factors`, which refuse elements outside their
    enumerations or that don't reference an Access Rights object.
    `bacnet-encoding` adds codecs for the two element types and for
    BACnetAuthenticationFactor, `bacnet-types` adds the
    `AccessAuthenticationFactorDisable` and `AuthenticationFactorType`
    enumerations and the element structs, and `BACnetAssignedAccessRights` now
    holds a `BACnetDeviceObjectReference` instead of an object identifier.
  - Access Door (Clause 12.26, Table 12-30) gains Door_Pulse_Time (default
    5 s), Door_Extended_Pulse_Time (15 s) and Door_Open_Too_Long_Time (30 s),
    all writable Unsigned32 counts of tenths of a second, and the read-only
    Current_Command_Priority, NULL while Present_Value comes from
    Relinquish_Default. A PULSE_UNLOCK or EXTENDED_PULSE_UNLOCK command is
    relinquished from its slot once its pulse time has passed, so the door
    relocks; the server's existing monotonic operation task, which also runs
    Binary Lighting Output egress, does this and sends COV. A pulse written
    below a slot already in use, or with a pulse time of zero, is relinquished
    at once. Door_Open_Too_Long_Time is stored but no alarm logic uses it.
    Relinquish_Default now refuses the two pulse values with
    VALUE_OUT_OF_RANGE, as Clause 12.26.11 allows only LOCK and UNLOCK there.
