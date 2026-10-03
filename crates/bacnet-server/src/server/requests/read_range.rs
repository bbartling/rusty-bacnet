use super::*;
use crate::device_view::{DeviceExecution, DeviceReadContext};
use bacnet_services::read_range::ReadRangeRequest;

/// ReadRange under one database read guard, through the same executor Device
/// view as ReadProperty (#1046). A request for the selected Device's
/// `Active_COV_Subscriptions` or `Active_COV_Multiple_Subscriptions`, or for
/// a Group's Present_Value whose members name them (#1171), samples the COV
/// table once, after the database guard (the server lock order), so every
/// item, flag and count of the page comes from one instant. The page follows
/// the configured ReadRange budget, and a Group's Present_Value counts
/// against the ReadPropertyMultiple work limit as in ReadProperty (#1172).
pub(super) async fn response(
    db: &RwLock<ObjectDatabase>,
    cov_table: &RwLock<CovSubscriptionTable>,
    request: &ConfirmedRequestPdu,
    config: &ServerConfig,
    effective_max_apdu: u16,
    segmented_response_available: bool,
    completed: impl FnOnce(
        &ObjectDatabase,
        ObjectIdentifier,
        PropertyIdentifier,
        Option<u32>,
        &Result<(), Error>,
    ),
) -> Apdu {
    let mut budget = config.read_range_budget;
    if !segmented_response_available {
        budget.max_service_ack_bytes = budget.max_service_ack_bytes.min(
            event_information::unsegmented_complex_ack_service_budget(
                request.invoke_id,
                request.service_choice,
                effective_max_apdu,
            ),
        );
    }
    let mut service_ack = BytesMut::new();
    let db = db.read().await;
    let result = match ReadRangeRequest::decode(&request.service_request) {
        Ok(decoded) => {
            let live = match handlers::active_cov_device(
                &db,
                decoded.object_identifier,
                decoded.property_identifier,
            ) {
                Some(selection) => {
                    Some(confirmed_response::active_cov_snapshot(&db, cov_table, selection).await)
                }
                None => None,
            };
            let view = DeviceReadContext::new(&db, DeviceExecution::FullServer, live.as_ref())
                .with_work_limit(config.read_property_multiple_budget.max_result_elements);
            handlers::read_range_request_observed(
                &db,
                Some(&view),
                decoded,
                &mut service_ack,
                budget,
                |target, property, index, result| completed(&db, target, property, index, result),
            )
        }
        Err(error) => Err(handlers::ReadRangeFailure::Service(error)),
    };
    match result {
        Ok(()) => Apdu::ComplexAck(ComplexAck {
            segmented: false,
            more_follows: false,
            invoke_id: request.invoke_id,
            sequence_number: None,
            proposed_window_size: None,
            service_choice: request.service_choice,
            service_ack: service_ack.freeze(),
        }),
        Err(handlers::ReadRangeFailure::Service(error)) => {
            confirmed_response::error_apdu_from_error(
                request.invoke_id,
                request.service_choice,
                &error,
            )
        }
        Err(handlers::ReadRangeFailure::Bytes) => Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id: request.invoke_id,
            abort_reason: AbortReason::BUFFER_OVERFLOW,
        }),
        Err(handlers::ReadRangeFailure::Work) => Apdu::Abort(AbortPdu {
            sent_by_server: true,
            invoke_id: request.invoke_id,
            abort_reason: AbortReason::OUT_OF_RESOURCES,
        }),
    }
}
