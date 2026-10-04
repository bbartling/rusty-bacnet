use std::sync::Arc;

use super::*;

#[test]
fn a_new_comm_state_is_enabled() {
    let state = CommState::default();
    assert_eq!(state.get(), DccState::Enable);
    assert!(!state.initiation_restricted());
    assert_eq!(DccState::default(), DccState::Enable);
}

#[test]
fn set_switches_between_the_two_states_and_back() {
    let state = CommState::default();
    state.set(DccState::DisableInitiation);
    assert_eq!(state.get(), DccState::DisableInitiation);
    assert!(state.initiation_restricted());
    // Setting the state it is already in leaves it there.
    state.set(DccState::DisableInitiation);
    assert_eq!(state.get(), DccState::DisableInitiation);
    state.set(DccState::Enable);
    assert_eq!(state.get(), DccState::Enable);
    assert!(!state.initiation_restricted());
}

#[test]
fn every_holder_of_a_shared_state_sees_a_change() {
    let state = Arc::new(CommState::default());
    let reader = Arc::clone(&state);
    std::thread::spawn(move || state.set_for_test(DccState::DisableInitiation))
        .join()
        .unwrap();
    assert_eq!(reader.get(), DccState::DisableInitiation);
    assert!(reader.initiation_restricted());
}

#[test]
fn only_disable_initiation_restricts_initiation() {
    assert!(!DccState::Enable.initiation_restricted());
    assert!(DccState::DisableInitiation.initiation_restricted());
}

#[test]
fn each_state_maps_to_its_enable_disable_value_and_none_to_disable() {
    for (state, wire) in [
        (DccState::Enable, EnableDisable::ENABLE),
        (
            DccState::DisableInitiation,
            EnableDisable::DISABLE_INITIATION,
        ),
    ] {
        let mapped = EnableDisable::from(state);
        assert_eq!(mapped, wire);
        assert_ne!(mapped, EnableDisable::DISABLE);
    }
    assert_eq!(EnableDisable::from(DccState::Enable).to_raw(), 0);
    assert_eq!(EnableDisable::from(DccState::DisableInitiation).to_raw(), 2);
}
