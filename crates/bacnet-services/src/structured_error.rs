//! The Clause 21 error productions that replace the plain class/code pair,
//! read by the service the Error PDU answers:
//!
//! | Service | Body |
//! |---|---|
//! | AddListElement, RemoveListElement | [`ChangeListError`] |
//! | CreateObject | [`CreateObjectError`] |
//! | WritePropertyMultiple | [`WritePropertyMultipleError`] |
//! | SubscribeCOVPropertyMultiple | [`SubscribeCOVPropertyMultipleError`] |
//! | ConfirmedPrivateTransfer | [`PrivateTransferError`] |
//! | VT-Close | [`VTCloseError`] |

use crate::cov_multiple::SubscribeCOVPropertyMultipleError;
use crate::list_manipulation::ChangeListError;
use crate::object_mgmt::CreateObjectError;
use crate::private_transfer::PrivateTransferError;
use crate::virtual_terminal::VTCloseError;
use crate::wpm::WritePropertyMultipleError;
use bacnet_encoding::apdu::ErrorPdu;
use bacnet_types::enums::ConfirmedServiceChoice;
use bacnet_types::error::{Error, ErrorDetail};

/// The detail `pdu`'s structured body adds to its class and code. `None` for
/// a plain class/code error, for a service with no structured body, and for
/// a body whose optional fields are all absent (SubscribeCOVPropertyMultiple's
/// general error, VTClose-Error without its list).
pub fn detail(pdu: &ErrorPdu) -> Option<ErrorDetail> {
    let service = pdu.service_choice;
    let error = if service == ConfirmedServiceChoice::ADD_LIST_ELEMENT
        || service == ConfirmedServiceChoice::REMOVE_LIST_ELEMENT
    {
        ChangeListError::try_from(pdu).map(Error::from)
    } else if service == ConfirmedServiceChoice::CREATE_OBJECT {
        CreateObjectError::try_from(pdu).map(Error::from)
    } else if service == ConfirmedServiceChoice::WRITE_PROPERTY_MULTIPLE {
        WritePropertyMultipleError::try_from(pdu).map(Error::from)
    } else if service == ConfirmedServiceChoice::SUBSCRIBE_COV_PROPERTY_MULTIPLE {
        SubscribeCOVPropertyMultipleError::try_from(pdu).map(Error::from)
    } else if service == ConfirmedServiceChoice::CONFIRMED_PRIVATE_TRANSFER {
        PrivateTransferError::try_from(pdu).map(Error::from)
    } else if service == ConfirmedServiceChoice::VT_CLOSE {
        VTCloseError::try_from(pdu).map(Error::from)
    } else {
        return None;
    };
    match error {
        Ok(Error::Structured { detail, .. }) => Some(*detail),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bacnet_types::constructed::BACnetObjectPropertyReference;
    use bacnet_types::enums::{ErrorClass, ErrorCode, ObjectType, PropertyIdentifier};
    use bacnet_types::primitives::ObjectIdentifier;
    use bytes::Bytes;

    #[test]
    fn each_service_reads_its_own_body() {
        let reference = BACnetObjectPropertyReference {
            object_identifier: ObjectIdentifier::new(ObjectType::ANALOG_VALUE, 1).unwrap(),
            property_identifier: PropertyIdentifier::PRESENT_VALUE.to_raw(),
            property_array_index: None,
        };
        let (class, code) = (ErrorClass::PROPERTY, ErrorCode::WRITE_ACCESS_DENIED);
        let cases = [
            (
                ChangeListError {
                    error_class: class,
                    error_code: code,
                    first_failed_element_number: 2,
                }
                .to_error_pdu(1, ConfirmedServiceChoice::REMOVE_LIST_ELEMENT),
                Some(ErrorDetail::FirstFailedElementNumber(2)),
            ),
            (
                CreateObjectError {
                    error_class: class,
                    error_code: code,
                    first_failed_element_number: 3,
                }
                .to_error_pdu(1),
                Some(ErrorDetail::FirstFailedElementNumber(3)),
            ),
            (
                WritePropertyMultipleError {
                    error_class: class,
                    error_code: code,
                    first_failed_write_attempt: reference.clone(),
                }
                .to_error_pdu(1),
                Some(ErrorDetail::FirstFailedWriteAttempt(reference.clone())),
            ),
            (
                SubscribeCOVPropertyMultipleError {
                    error_class: class,
                    error_code: code,
                    first_failed_subscription: Some(reference.clone()),
                }
                .to_error_pdu(1),
                Some(ErrorDetail::FirstFailedSubscription(reference.clone())),
            ),
            (
                SubscribeCOVPropertyMultipleError {
                    error_class: class,
                    error_code: code,
                    first_failed_subscription: None,
                }
                .to_error_pdu(1),
                None,
            ),
            (
                PrivateTransferError {
                    error_class: class,
                    error_code: code,
                    vendor_id: 9,
                    service_number: 1,
                    error_parameters: None,
                }
                .to_error_pdu(1),
                Some(ErrorDetail::PrivateTransfer {
                    vendor_id: 9,
                    service_number: 1,
                    error_parameters: None,
                }),
            ),
            (
                VTCloseError {
                    error_class: class,
                    error_code: code,
                    list_of_vt_session_identifiers: Some(vec![3]),
                }
                .to_error_pdu(1),
                Some(ErrorDetail::VtSessionIdentifiers(vec![3])),
            ),
        ];
        for (pdu, expected) in cases {
            assert_eq!(detail(&pdu), expected, "{:?}", pdu.service_choice);
            // The same body under a service without one, or a plain error
            // under the right service, has no detail.
            let mut other = pdu.clone();
            other.service_choice = ConfirmedServiceChoice::READ_PROPERTY;
            assert_eq!(detail(&other), None);
            let mut plain = pdu;
            plain.error_data = Bytes::new();
            assert_eq!(detail(&plain), None);
        }
    }
}
