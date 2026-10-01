use super::*;

#[cfg(test)]
#[path = "dcc_disable_rate_tests.rs"]
mod rate_tests;

pub(super) async fn response<T: TransportPort + 'static>(
    services: &RequestServices<T>,
    req: &ConfirmedRequestPdu,
    source_mac: &[u8],
    source: Option<&NpduAddress>,
    request_tasks: &super::super::request_tasks::RequestTaskSpawner,
) -> Apdu {
    let RequestServices {
        dcc_timer: timer,
        comm_state,
        dcc_outcomes: outcomes,
        config,
        cov_table,
        ..
    } = services;
    let cov_resume = cov_table.read().await.timed().clone();
    let result = super::super::dcc_timer::replace(
        timer,
        comm_state,
        super::super::dcc_timer::DccRequest {
            service_data: &req.service_request,
            source_mac,
            source,
        },
        config,
        request_tasks,
        &cov_resume,
    )
    .await;
    // No await between validation failure/live commit and completion telemetry.
    // The counter and event happen before constructing either response.
    match result {
        Ok(metadata) => {
            outcomes.record(
                dcc_outcomes::DccOutcome::Accepted,
                metadata,
                req.invoke_id,
                source_mac,
                source,
            );
            Apdu::SimpleAck(SimpleAck {
                invoke_id: req.invoke_id,
                service_choice: req.service_choice,
            })
        }
        Err(failure) => {
            outcomes.record(
                failure.outcome,
                failure.metadata,
                req.invoke_id,
                source_mac,
                source,
            );
            BACnetServer::<T>::error_apdu_from_error(
                req.invoke_id,
                req.service_choice,
                &failure.error,
            )
        }
    }
}
