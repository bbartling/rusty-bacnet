//! Passing a Channel object's Present_Value on to its members (Clause 12.53,
//! #1151).
//!
//! Each member's Execution_Delay is measured from the moment the
//! distribution starts, so the delays overlap rather than add up
//! (Clause 12.53.12): the members go in order of delay, list order among
//! equal delays, each as soon as its time is reached.
//!
//! For each member the runner looks up the datatype of the property's current
//! value, coerces the channel value to it (Table 12-63) and writes the result
//! through the host's write path at the priority the Present_Value write
//! carried, or none if it carried none. A coercion failure means that member
//! isn't written. A refused write counts as a failure too, with one
//! exception: a NULL refused as an invalid datatype, so one channel can
//! relinquish its commandable members while its other members ignore the
//! NULL (Clause 12.53.7). One failure doesn't stop the rest
//! (Clause 12.53.5.8); once every member has been tried, the Channel's
//! Write_Status becomes SUCCESSFUL or FAILED.

use bacnet_objects::channel::{
    coerce_channel_value, ChannelDistribution, ChannelMember, MemberDatatype,
};
use bacnet_objects::command::CommandRun;
use bacnet_types::constructed::BACnetActionCommand;
use bacnet_types::enums::{ErrorCode, PropertyIdentifier};
use bacnet_types::error::Error;
use bacnet_types::primitives::PropertyValue;
use tracing::debug;

use super::{Owner, RunHost};

/// Write each member once its delay is up: whether all succeeded, or `None`
/// once the run is stale.
pub(super) async fn distribute<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    owner: &mut Owner<'_, H>,
) -> Option<bool> {
    let start = tokio::time::Instant::now();
    let mut members: Vec<&ChannelMember> = distribution.members.iter().collect();
    members.sort_by_key(|member| member.delay_ms);
    let mut all_succeeded = true;
    for (written, member) in members.into_iter().enumerate() {
        if member.delay_ms > 0 {
            let due = start + std::time::Duration::from_millis(member.delay_ms.into());
            tokio::time::sleep_until(due).await;
        }
        all_succeeded &= write_member(host, run, distribution, member).await?;
        owner.progress(written + 1, all_succeeded);
    }
    Some(all_succeeded)
}

/// Write one member; whether that counts as a success. `None` once the run
/// is stale.
async fn write_member<H: RunHost>(
    host: &H,
    run: &CommandRun,
    distribution: &ChannelDistribution,
    member: &ChannelMember,
) -> Option<bool> {
    let reference = &member.reference;
    let property = PropertyIdentifier::from_raw(reference.property_identifier);
    let datatype = {
        let db = host.database().read().await;
        if db
            .get(&run.source)
            .and_then(|object| object.command_generation_internal())
            != Some(run.generation)
        {
            return None;
        }
        let current = db.get(&reference.object_identifier).and_then(|object| {
            object
                .read_property(property, reference.property_array_index)
                .ok()
        });
        MemberDatatype::of(property, current.as_ref())
    };
    let Ok(value) = coerce_channel_value(&distribution.value, datatype) else {
        debug!(
            channel = %run.source,
            target = %reference.object_identifier,
            ?property,
            ?datatype,
            "Channel value can't be coerced to the member's datatype"
        );
        return Some(false);
    };
    let command = BACnetActionCommand {
        device_identifier: None,
        object_identifier: reference.object_identifier,
        property_identifier: property,
        property_array_index: reference.property_array_index,
        property_value: value,
        priority: distribution.priority,
        post_delay: None,
        quit_on_failure: false,
        write_successful: false,
    };
    match host.write(run, &command).await {
        Ok(()) => Some(true),
        Err(error)
            if command.property_value == PropertyValue::Null && is_invalid_datatype(&error) =>
        {
            Some(true)
        }
        Err(error) => {
            debug!(
                channel = %run.source,
                target = %reference.object_identifier,
                ?property,
                %error,
                "Channel member write failed"
            );
            Some(false)
        }
    }
}

/// Whether a refused write named the value's datatype as the reason.
fn is_invalid_datatype(error: &Error) -> bool {
    let invalid = ErrorCode::INVALID_DATA_TYPE.to_raw() as u32;
    matches!(
        error,
        Error::Protocol { code, .. } | Error::Structured { code, .. } if *code == invalid
    )
}
