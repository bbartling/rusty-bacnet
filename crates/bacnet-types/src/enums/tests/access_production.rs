//! Clause 21 values of the access-control enumerations the Access Credential's
//! arrays (#1073) and the Access Rights rules (#1316) carry.

use super::*;

/// 135-2020 Clause 21: the six named authentication-factor disable values an
/// Access Credential's factors carry (#1073).
#[test]
fn access_authentication_factor_disable_values_match_clause_21() {
    assert_production_values!(
        AccessAuthenticationFactorDisable,
        [
            ("NONE", 0),
            ("DISABLED", 1),
            ("DISABLED_LOST", 2),
            ("DISABLED_STOLEN", 3),
            ("DISABLED_DAMAGED", 4),
            ("DISABLED_DESTROYED", 5),
        ],
    );
}

/// 135-2020 Clause 21: the closed set of 25 authentication factor formats,
/// numbered 0 to 24 in declaration order (#1073).
#[test]
fn authentication_factor_type_values_match_clause_21() {
    let names = [
        "UNDEFINED",
        "ERROR",
        "CUSTOM",
        "SIMPLE_NUMBER16",
        "SIMPLE_NUMBER32",
        "SIMPLE_NUMBER56",
        "SIMPLE_ALPHA_NUMERIC",
        "ABA_TRACK2",
        "WIEGAND26",
        "WIEGAND37",
        "WIEGAND37_FACILITY",
        "FACILITY16_CARD32",
        "FACILITY32_CARD32",
        "FASC_N",
        "FASC_N_BCD",
        "FASC_N_LARGE",
        "FASC_N_LARGE_BCD",
        "GSA75",
        "CHUID",
        "CHUID_FULL",
        "GUID",
        "CBEFF_A",
        "CBEFF_B",
        "CBEFF_C",
        "USER_PASSWORD",
    ];
    assert_eq!(AuthenticationFactorType::ALL_NAMED.len(), names.len());
    for (raw, (name, &(named, value))) in names
        .iter()
        .zip(AuthenticationFactorType::ALL_NAMED)
        .enumerate()
    {
        assert_eq!((named, value.to_raw()), (*name, raw as u32));
        assert_eq!(format!("{value}"), *name);
    }
}

/// 135-2020 Clause 21: the two specifiers of a BACnetAccessRule, each a
/// closed pair numbered 0 and 1 (#1316).
#[test]
fn access_rule_specifier_values_match_clause_21() {
    assert_production_values!(
        AccessRuleTimeRangeSpecifier,
        [("SPECIFIED", 0), ("ALWAYS", 1)]
    );
    assert_production_values!(AccessRuleLocationSpecifier, [("SPECIFIED", 0), ("ALL", 1)]);
}
