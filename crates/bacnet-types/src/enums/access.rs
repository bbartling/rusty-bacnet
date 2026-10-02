// ===========================================================================
// Door / access control enums (Clause 12.26, 12.33)
// ===========================================================================

bacnet_enum! {
    /// BACnet door alarm state (Clause 12.26).
    pub struct DoorAlarmState(u32);

    const NORMAL = 0;
    const ALARM = 1;
    const DOOR_OPEN_TOO_LONG = 2;
    const FORCED_OPEN = 3;
    const TAMPER = 4;
    const DOOR_FAULT = 5;
    const LOCK_DOWN = 6;
    const FREE_ACCESS = 7;
    const EGRESS_OPEN = 8;
}

bacnet_enum! {
    /// BACnet door status (Clause 12.26).
    pub struct DoorStatus(u32);

    const CLOSED = 0;
    const OPENED = 1;
    const UNKNOWN = 2;
    const DOOR_FAULT = 3;
    const UNUSED = 4;
    const NONE = 5;
    const CLOSING = 6;
    const OPENING = 7;
    const SAFETY_LOCKED = 8;
    const LIMITED_OPENED = 9;
}

bacnet_enum! {
    /// BACnet lock status (Clause 12.26).
    pub struct LockStatus(u32);

    const LOCKED = 0;
    const UNLOCKED = 1;
    const LOCK_FAULT = 2;
    const UNUSED = 3;
    const UNKNOWN = 4;
}

bacnet_enum! {
    /// BACnet secured status for Access Door (Clause 12.26).
    pub struct DoorSecuredStatus(u32);

    const SECURED = 0;
    const UNSECURED = 1;
    const UNKNOWN = 2;
}

bacnet_enum! {
    /// BACnet door command for Access Door present values (Clause 21).
    pub struct DoorValue(u32);

    const LOCK = 0;
    const UNLOCK = 1;
    const PULSE_UNLOCK = 2;
    const EXTENDED_PULSE_UNLOCK = 3;
}

bacnet_enum! {
    /// BACnet access event (Clause 12.33).
    pub struct AccessEvent(u32);

    const NONE = 0;
    const GRANTED = 1;
    const MUSTER = 2;
    const PASSBACK_DETECTED = 3;
    const DURESS = 4;
    const TRACE = 5;
    const LOCKOUT_MAX_ATTEMPTS = 6;
    const LOCKOUT_OTHER = 7;
    const LOCKOUT_RELINQUISHED = 8;
    const LOCKED_BY_HIGHER_PRIORITY = 9;
    const OUT_OF_SERVICE = 10;
    const OUT_OF_SERVICE_RELINQUISHED = 11;
    const ACCOMPANIMENT_BY = 12;
    const AUTHENTICATION_FACTOR_READ = 13;
    const AUTHORIZATION_DELAYED = 14;
    const VERIFICATION_REQUIRED = 15;
    const NO_ENTRY_AFTER_GRANTED = 16;
    // Denied events (128+)
    const DENIED_DENY_ALL = 128;
    const DENIED_UNKNOWN_CREDENTIAL = 129;
    const DENIED_AUTHENTICATION_UNAVAILABLE = 130;
    const DENIED_AUTHENTICATION_FACTOR_TIMEOUT = 131;
    const DENIED_INCORRECT_AUTHENTICATION_FACTOR = 132;
    const DENIED_ZONE_NO_ACCESS_RIGHTS = 133;
    const DENIED_POINT_NO_ACCESS_RIGHTS = 134;
    const DENIED_NO_ACCESS_RIGHTS = 135;
    const DENIED_OUT_OF_TIME_RANGE = 136;
    const DENIED_THREAT_LEVEL = 137;
    const DENIED_PASSBACK = 138;
    const DENIED_UNEXPECTED_LOCATION_USAGE = 139;
    const DENIED_MAX_ATTEMPTS = 140;
    const DENIED_LOWER_OCCUPANCY_LIMIT = 141;
    const DENIED_UPPER_OCCUPANCY_LIMIT = 142;
    const DENIED_AUTHENTICATION_FACTOR_LOST = 143;
    const DENIED_AUTHENTICATION_FACTOR_STOLEN = 144;
    const DENIED_AUTHENTICATION_FACTOR_DAMAGED = 145;
    const DENIED_AUTHENTICATION_FACTOR_DESTROYED = 146;
    const DENIED_AUTHENTICATION_FACTOR_DISABLED = 147;
    const DENIED_AUTHENTICATION_FACTOR_ERROR = 148;
    const DENIED_CREDENTIAL_UNASSIGNED = 149;
    const DENIED_CREDENTIAL_NOT_PROVISIONED = 150;
    const DENIED_CREDENTIAL_NOT_YET_ACTIVE = 151;
    const DENIED_CREDENTIAL_EXPIRED = 152;
    const DENIED_CREDENTIAL_MANUAL_DISABLE = 153;
    const DENIED_CREDENTIAL_LOCKOUT = 154;
    const DENIED_CREDENTIAL_MAX_DAYS = 155;
    const DENIED_CREDENTIAL_MAX_USES = 156;
    const DENIED_CREDENTIAL_INACTIVITY = 157;
    const DENIED_CREDENTIAL_DISABLED = 158;
    const DENIED_NO_ACCOMPANIMENT = 159;
    const DENIED_INCORRECT_ACCOMPANIMENT = 160;
    const DENIED_LOCKOUT = 161;
    const DENIED_VERIFICATION_FAILED = 162;
    const DENIED_VERIFICATION_TIMEOUT = 163;
    const DENIED_OTHER = 164;
}

bacnet_enum! {
    /// BACnet access credential disable (Clause 21).
    pub struct AccessCredentialDisable(u32);

    const NONE = 0;
    const DISABLE = 1;
    const DISABLE_MANUAL = 2;
    const DISABLE_LOCKOUT = 3;
}

bacnet_enum! {
    /// BACnet access credential disable reason (Clause 21).
    pub struct AccessCredentialDisableReason(u32);

    const DISABLED = 0;
    const DISABLED_NEEDS_PROVISIONING = 1;
    const DISABLED_UNASSIGNED = 2;
    const DISABLED_NOT_YET_ACTIVE = 3;
    const DISABLED_EXPIRED = 4;
    const DISABLED_LOCKOUT = 5;
    const DISABLED_MAX_DAYS = 6;
    const DISABLED_MAX_USES = 7;
    const DISABLED_INACTIVITY = 8;
    const DISABLED_MANUAL = 9;
}

bacnet_enum! {
    /// Whether one authentication factor of an Access Credential may be used,
    /// and if not why: the disable member of each Authentication_Factors
    /// element (Table 12-40; Clause 21 production). ASHRAE owns 0 to 63 and
    /// 64 to 65535 are open to vendors.
    pub struct AccessAuthenticationFactorDisable(u32);

    const NONE = 0;
    const DISABLED = 1;
    const DISABLED_LOST = 2;
    const DISABLED_STOLEN = 3;
    const DISABLED_DAMAGED = 4;
    const DISABLED_DESTROYED = 5;
}

bacnet_enum! {
    /// The format of an authentication factor's value (Clause 21 production;
    /// Annex P describes each format). The production is closed: it has no
    /// vendor range.
    pub struct AuthenticationFactorType(u32);

    const UNDEFINED = 0;
    const ERROR = 1;
    const CUSTOM = 2;
    const SIMPLE_NUMBER16 = 3;
    const SIMPLE_NUMBER32 = 4;
    const SIMPLE_NUMBER56 = 5;
    const SIMPLE_ALPHA_NUMERIC = 6;
    const ABA_TRACK2 = 7;
    const WIEGAND26 = 8;
    const WIEGAND37 = 9;
    const WIEGAND37_FACILITY = 10;
    const FACILITY16_CARD32 = 11;
    const FACILITY32_CARD32 = 12;
    const FASC_N = 13;
    const FASC_N_BCD = 14;
    const FASC_N_LARGE = 15;
    const FASC_N_LARGE_BCD = 16;
    const GSA75 = 17;
    const CHUID = 18;
    const CHUID_FULL = 19;
    const GUID = 20;
    const CBEFF_A = 21;
    const CBEFF_B = 22;
    const CBEFF_C = 23;
    const USER_PASSWORD = 24;
}

bacnet_enum! {
    /// BACnet authentication status: the Access Point object's
    /// Authentication_Status property (Table 12-36; Clause 21 production).
    pub struct AuthenticationStatus(u32);

    const NOT_READY = 0;
    const READY = 1;
    const DISABLED = 2;
    const WAITING_FOR_AUTHENTICATION_FACTOR = 3;
    const WAITING_FOR_ACCOMPANIMENT = 4;
    const WAITING_FOR_VERIFICATION = 5;
    const IN_PROGRESS = 6;
}

bacnet_enum! {
    /// BACnet access user type (Clause 12.33; Clause 21.6 production).
    pub struct AccessUserType(u32);

    const ASSET = 0;
    const GROUP = 1;
    const PERSON = 2;
}

bacnet_enum! {
    /// BACnet authorization mode (Clause 12.31).
    pub struct AuthorizationMode(u32);

    const AUTHORIZE = 0;
    const GRANT_ACTIVE = 1;
    const DENY_ALL = 2;
    const VERIFICATION_REQUIRED = 3;
    const AUTHORIZATION_DELAYED = 4;
    const NONE = 5;
}

bacnet_enum! {
    /// BACnet authorization check a credential is exempt from (Clause 21).
    pub struct AuthorizationExemption(u32);

    const PASSBACK = 0;
    const OCCUPANCY_CHECK = 1;
    const ACCESS_RIGHTS = 2;
    const LOCKOUT = 3;
    const DENY = 4;
    const VERIFICATION = 5;
    const AUTHORIZATION_DELAY = 6;
}

bacnet_enum! {
    /// BACnet access passback mode (Clause 12.32).
    pub struct AccessPassbackMode(u32);

    const PASSBACK_OFF = 0;
    const HARD_PASSBACK = 1;
    const SOFT_PASSBACK = 2;
}

bacnet_enum! {
    /// BACnet access zone occupancy state (Clause 21).
    pub struct AccessZoneOccupancyState(u32);

    const NORMAL = 0;
    const BELOW_LOWER_LIMIT = 1;
    const AT_LOWER_LIMIT = 2;
    const AT_UPPER_LIMIT = 3;
    const ABOVE_UPPER_LIMIT = 4;
    const DISABLED = 5;
    const NOT_SUPPORTED = 6;
}
